import datetime
import json
import logging
import os
import paramiko
import pynetbox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import traceback
import time
import warnings
import yaml


class ConnectionArgs:
    # Configuring class attributes to store applications platform secrets
    connection_dict = yaml.safe_load(open("/platform/secret/secret.yml"))
    f5_username = connection_dict["F5_MGMT_USERNAME"]
    f5_password = connection_dict["F5_MGMT_PASSWORD"]
    vm_username = connection_dict["SERVICE_ACCOUNT_USERNAME"]
    vm_password = connection_dict["SERVICE_ACCOUNT_PASSWORD"]
    netbox_token = connection_dict["NETBOX_TOKEN"]


def get_f5_netbox_hosts(netbox_token):
    """
    Get F5 load balancer host names from NetBox.
    """
    # Configure Netbox API connection before use
    netbox_api_object = pynetbox.api(
        url="https://netbox.prod.widgets.com",
        token=netbox_token,
    )
    requests_session_object = requests.Session()
    requests_session_object.verify = os.environ.get("CERT_AUTH_BUNDLE")
    netbox_api_object.http_session = requests_session_object
    ####
    # Get F5 load balancer device information from Netbox API
    try:
        netbox_host_object_list = netbox_api_object.dcim.devices.filter(
            status="active",
            tag="f5",
        )
    except pynetbox.lib.query.RequestError as error_object:
        print(error_object.error)
    nb_host_strings_list = []
    for host_object in netbox_host_object_list:
        nb_host_strings_list.append(host_object.name)
    return nb_host_strings_list


def create_backup_file_on_f5(f5_hostname, f5_username, f5_password):
    """
    Create a new backup file on an F5 load-balancer.
    May take as long as 500 seconds for the new backup file to be available.
    """
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    time_string = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    filepath = f"/temp/{f5_hostname}_{time_string}_backuptest.ucs"
    url = f"https://{f5_hostname}-central.widgets.com/mgmt/tm/sys/ucs"
    request_headers = {"Content-Type": "application/json", "Authorization": "Basic "}
    request_dict = {"command": "save", "name": filepath}
    request_body = json.dumps(request_dict)
    try:
        response_object = requests.post(
            url,
            data=request_body,
            headers=request_headers,
            verify=False,
            auth=requests.auth.HTTPBasicAuth(f5_username, f5_password),
        )
        response_object.raise_for_status()
    except requests.exceptions.HTTPError as error_object:
        print(
            f"{type(error_object)} F5 web API call failed to create new .ucs backup on {f5_hostname}. Response: {response_object.status_code} - {response_object.text}. ({error_object})"
        )
        backup_filename = None
    except:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        traceback_list = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        traceback_string = " ".join(traceback_list)
        print(
            f"{exception_type}: attempt to create new .ucs backup for {f5_hostname} failed. Traceback: {traceback_string}"
        )
        backup_filename = None
    else:
        # The try-except statement has an optional else clause
        # for code that will be executed if the try clause succeeds.
        response_object.encoding = "UTF-8"
        result_dict = json.loads(response_object.text)
        print(f"Requesting new backup file on {f5_hostname} at {result_dict['name']}")
        if result_dict.get("name"):
            backup_filename = result_dict.get("name").replace("/temp/", "")
        else:
            backup_filename = None
    return backup_filename


def scp_with_paramiko_no_shell(
    vm_host,
    vm_username,
    vm_password,
    f5_username,
    f5_password,
    f5_host,
    backup_filename,
):
    """
    SSH to a virtual machine then SCP a file from an F5 loadbalancer to the virtual machine.
    """
    paramiko_logger = paramiko.util.logging.getLogger()
    paramiko_logger.setLevel(logging.WARN)
    ssh_port = 22
    f5_filepath = f"/temp/{backup_filename}"
    future_vm_filepath = f"/home/{vm_username}/backups/{backup_filename}"
    command_string = f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {f5_username}@{f5_host}-central.widgets.com:{f5_filepath} {future_vm_filepath}"
    print(f"Preparing to copy {backup_filename} from {f5_host} to {vm_host}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # timeout (float) – an optional timeout (in seconds) for the TCP connect
        client.connect(
            f"{vm_host}.central.widgets.com",
            ssh_port,
            f5_username,
            vm_password,
            look_for_keys=False,
            timeout=6000,
        )
        stdin, stdout, stderr = client.exec_command(command_string, get_pty=True)

        # Monitor standard out for the 'Password:' prompt
        standard_out_string = ""
        for loop in range(0, 1200):
            if stdout.channel.recv_ready():
                stdout_character = stdout.read(1)
                standard_out_string = standard_out_string + stdout_character.decode(
                    encoding="UTF-8"
                )
                # Check for password prompt or nothing further to read
                if "Password:".lower() in standard_out_string.lower():
                    break
                if len(stdout_character) == 0:
                    break
            time.sleep(0.01)
        compressed_stdout = (
            standard_out_string.strip().replace("\n", " ").replace("\r", " ")
        )
        print(f"Password loop standard out is {compressed_stdout}")

        # Now try sending the password for the F5
        stdin.write(f5_password)
        stdin.write("\n")
        stdin.flush()

        # Log output
        stdout_string = stdout.read()
        output_string = (
            stdout_string.decode(encoding="UTF-8").strip().replace("\n", " ")
        )
        print(f"Post-SCP standard out: {output_string}")

        # Using stdout.channel.recv_exit_status() to check the exit code.
        # This blocks the progress of the code until an exit status is available,
        # which keeps Paramiko from closing the connection prematurely.
        exit_code = stdout.channel.recv_exit_status()

    except paramiko.ssh_exception.AuthenticationException:
        print(
            f"Attempt to authenticate to host {vm_host} for scp failed: {sys.exc_info()[0]}"
        )
        exit_code = 1
    except paramiko.SSHException as ssh_exception_object:
        print(
            f"An exception occurred while attempting to scp a file from F5 host {vm_host}: {str(ssh_exception_object)}"
        )
        exit_code = 1
    except:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        print(
            f"An exception occurred while attempting to scp a file from F5 host {vm_host}: {exception_type}"
        )
        traceback_list = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        traceback_string = " ".join(traceback_list).replace("\n", "  |  ")
        print(f"Traceback for {vm_host} exception  --->  {traceback_string}")
        exit_code = 1
    finally:
        client.close()
    return exit_code


def remove_backup_file_from_f5(host, f5_username, f5_password, backup_filename):
    paramiko_logger = paramiko.util.logging.getLogger()
    paramiko_logger.setLevel(logging.WARN)
    ssh_port = 22
    command_string = f"rm -f /temp/{backup_filename} && df -h --total | grep -i total"
    print(f"Connecting to {host} as {f5_username} to send command: {command_string}")
    try:
        ssh_connection = paramiko.SSHClient()
        ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connection.connect(
            f"{host}-central.widgets.com",
            ssh_port,
            f5_username,
            f5_password,
            timeout=6000,
        )
        stdin, stdout, stderr = ssh_connection.exec_command(command_string)
        stdout_string = stdout.read()
        output_string = stdout_string.decode(encoding="UTF-8").strip()
        print(f"Command {command_string} to F5 {host} output: {output_string}")
        exit_code = stdout.channel.recv_exit_status()
    except paramiko.ssh_exception.AuthenticationException:
        print(f"Authentication to {host} failed.")
        exit_code = 1
    except paramiko.SSHException as ssh_exception_object:
        print(
            f"An exception occurred during ssh to host {host}: {str(ssh_exception_object)}"
        )
        exit_code = 1
    except:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        print(f"An exception occurred during ssh to host {host}: {exception_type}")
        traceback_list = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        traceback_string = " ".join(traceback_list).replace("\n", "  |  ")
        print(f"Traceback for {host} exception  --->  {traceback_string}")
        exit_code = 1
    finally:
        ssh_connection.close()
    return exit_code


def list_backup_files_on_vm(hostname, vm_username, vm_password):
    paramiko_logger = paramiko.util.logging.getLogger()
    paramiko_logger.setLevel(logging.WARN)
    ssh_port = 22
    command_string = f"ls -lh /home/{vm_username}/backups/"
    print(
        f"Connecting to {hostname} as {vm_username} to send command: {command_string}"
    )
    try:
        ssh_connection = paramiko.SSHClient()
        ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connection.connect(
            f"{hostname}.central.widgets.com", ssh_port, vm_username, vm_password
        )
        stdin, stdout, stderr = ssh_connection.exec_command(command_string)
        stdout_string = stdout.read()
        output_string = (
            stdout_string.decode(encoding="UTF-8").strip().replace("\n", " ")
        )
        print(f"Command '{command_string}' to {hostname} output: {output_string}")
        exit_code = stdout.channel.recv_exit_status()
    except paramiko.ssh_exception.AuthenticationException:
        print(f"Authentication to {hostname} failed. {sys.exc_info()[0]}")
        exit_code = 1
    except paramiko.SSHException as ssh_exception_object:
        print(
            f"An exception occurred during ssh to host {hostname}:",
            str(ssh_exception_object),
        )
        exit_code = 1
    finally:
        ssh_connection.close()
    return exit_code


def remove_backup_files_from_vm(hostname, vm_username, vm_password):
    paramiko_logger = paramiko.util.logging.getLogger()
    paramiko_logger.setLevel(logging.WARN)
    ssh_port = 22
    # Command to remove any matching files older than 2 days
    command_string = (
        f"find /home/{vm_username}/backups/*.ucs -mtime +2 -exec rm {{}} \;"
    )
    print(
        f"Connecting to {hostname} as {vm_username} to send command: {command_string}"
    )
    try:
        ssh_connection = paramiko.SSHClient()
        ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_connection.connect(
            f"{hostname}.central.widgets.com", ssh_port, vm_username, vm_password
        )
        stdin, stdout, stderr = ssh_connection.exec_command(command_string)
        stdout_string = stdout.read()
        output_string = (
            stdout_string.decode(encoding="UTF-8").strip().replace("\n", " ")
        )
        exit_code = stdout.channel.recv_exit_status()
        print(
            f"Command '{command_string}' to {hostname} produced exit code {exit_code} and output: {output_string}"
        )
    except paramiko.ssh_exception.AuthenticationException:
        print(f"Authentication to {hostname} failed: {sys.exc_info()[0]}")
        exit_code = 1
    except paramiko.SSHException as ssh_exception_object:
        print(
            f"An exception occurred during ssh to host {hostname}: {str(ssh_exception_object)}"
        )
        exit_code = 1
    finally:
        ssh_connection.close()
    return exit_code


def send_metric(one_or_zero, f5_host):
    """
    Formats results for use by Grafana dashboard and sends them to platform metrics database.
    """
    # Table name
    table_name = "f5_logs"
    if f5_host.startswith("stage-site"):
        host_region = "stage-site"
        host_environment = "stage-test"
    elif f5_host.startswith("site2"):
        host_region = "site2"
        host_environment = "production"
    elif f5_host.startswith("site1"):
        host_region = "site1"
        host_environment = "production"
    else:
        host_region = "unknown"
        host_environment = "unknown"
        print(f"Unable to determine location of {f5_host}")

    filter_tags = f"_blossom_id=CI02945733,region={host_region},env={host_environment},host={f5_host}"

    # The field set (name and value) for the measurement, comma separated, followed by a space
    value_fields = f"backup={one_or_zero}"

    # Nanoseconds since epoch
    nanosec_string = str(time.time_ns())

    # Formatting the above information so it can be processed as metrics
    data_string = f"{table_name},{filter_tags} {value_fields} {nanosec_string}"

    # Web API endpoint for adding new information to platform metrics database
    url = "https://metrics-ingestion.widgets.com/write?db=metrics"

    # POST request to send metric
    headers = {"Content-Type": "text/plain"}
    request_body = data_string.encode("utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            response = requests.post(
                url, headers=headers, data=request_body, timeout=10, verify=False
            )
            response.raise_for_status()
            response.encoding = "UTF-8"
            print(
                f"BACKUP UPDATE: Sent {value_fields} metric for {f5_host}: {response.status_code}: {response.text}"
            )
        except requests.exceptions.RequestException as error_object:
            print(
                f"BACKUP UPDATE: POST Request to metrics front door for {f5_host} failed. {type(error_object)}: {error_object}"
            )


def create_f5_remote_backups():
    # Get service account auth information
    args_object = ConnectionArgs()
    vm_host = "lbsbackup001"

    # Get F5 hostnames from Netbox
    f5_hostname_list = get_f5_netbox_hosts(args_object.netbox_token)
    print(
        f"Found {len(f5_hostname_list)} hosts in Netbox: {', '.join(f5_hostname_list)}"
    )

    # Tell all the F5 load balancers to make backup files
    f5_backup_filename_dict = {}
    for f5_host in f5_hostname_list:
        backup_filename = create_backup_file_on_f5(
            f5_host, args_object.f5_username, args_object.f5_password
        )
        f5_backup_filename_dict[f5_host] = backup_filename

    # Wait for the back-up file/s to be prepared
    sleep_seconds_int = 500
    print(
        f"Pausing for {sleep_seconds_int} seconds while the F5 load balancers create their back-up files"
    )
    time.sleep(500)

    # scp the files created above from the F5s to the VM host used for storing backup files
    failure_list = []
    success_list = []
    for f5_host, backup_filename in f5_backup_filename_dict.items():
        if not backup_filename:
            print(f"No backup filename created for host {f5_host}")
            # Zero is failure in the Grafana dashboard
            send_metric("0", f5_host)
            failure_list.append(f5_host)
            continue

        exit_code = scp_with_paramiko_no_shell(
            vm_host,
            args_object.f5_username,
            args_object.f5_password,
            args_object.f5_username,
            args_object.f5_password,
            f5_host,
            backup_filename,
        )
        if exit_code != 0:
            print(f"SCP from F5 {f5_host} returned error code {exit_code}.")
            # Zero is failure in the Grafana dashboard
            send_metric("0", f5_host)
            failure_list.append(f5_host)
            remove_backup_file_from_f5(
                f5_host,
                args_object.f5_username,
                args_object.f5_password,
                backup_filename,
            )
            continue

        print(f"SCP from F5 {f5_host} returned success code {exit_code}.")
        exit_code = remove_backup_file_from_f5(
            f5_host, args_object.f5_username, args_object.f5_password, backup_filename
        )
        if exit_code != 0:
            print(
                f"File removal command sent to f5 {f5_host} returned error code {exit_code}."
            )
            # Zero is failure in the Grafana dashboard
            send_metric("0", f5_host)
            failure_list.append(f5_host)
        else:
            print(
                f"File removal command sent to f5 {f5_host} returned success code {exit_code}."
            )
            # One is success in the Grafana dashboard
            send_metric("1", f5_host)
            success_list.append(f5_host)

    list_backup_files_on_vm(vm_host, args_object.f5_username, args_object.f5_password)

    remove_backup_files_from_vm(
        vm_host, args_object.f5_username, args_object.f5_password
    )

    print(
        f"Completed F5 back-up jobs with {len(success_list)} of {len(f5_hostname_list)} successful."
    )
    if len(failure_list) > 0:
        print(f"F5 back-up job failures: {', '.join(failure_list)}")


if __name__ == "__main__":
    create_f5_remote_backups()
