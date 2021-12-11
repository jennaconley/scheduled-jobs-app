import json
import requests
import sys
import subprocess
import traceback
import yaml


class ConnectionArgs:
    # Configuring class attributes to store applications platform secrets
    connection_dict = yaml.safe_load(open("/platform/secret/secret.yml"))
    service_account_username = connection_dict["SERVICE_ACCOUNT_USERNAME"]
    adn_vip_password = connection_dict["SERVICE_ACCOUNT_PASSWORD"]
    cert_auth_bundle = "/app/ca-bundle.crt"


def renew_device_certs():
    """
    Makes an API call which begins renewal process for device certificates.
    """
    connection_args_object = ConnectionArgs()
    url_string = "https://device-management.widgets.com/cert-renew"
    command_list = [
        "curl",
        "-k",
        "-u",
        f"{connection_args_object.service_account_username}:{connection_args_object.adn_vip_password}",
        "-X",
        "POST",
        "-H",
        "Content-Type:application/json",
        url_string,
    ]
    command_string = " ".join(command_list)
    try:
        # If shell=True, on POSIX the executable argument specifies a replacement shell for the default /bin/sh.
        completed_process_object = subprocess.run(
            command_string, shell=True, capture_output=True, executable="/bin/sh"
        )
        # If returncode attribute is non-zero, .check_returncode() raises a CalledProcessError.
        completed_process_object.check_returncode()
        # print(f"Completed process: {completed_process_object.args}")
        # print(f"Completed process returncode: {completed_process_object.returncode}")
        # print(f"Completed process standard out is: {completed_process_object.stdout}")
        # Example responses:
        # {"results":"no cert to renew"}
        # {"results":"renewed certs: [\"CNG1914553\", \"CNG1914554\", \"CNG1914555\", \"CNG1914556\"]"}
        output_string = (
            completed_process_object.stdout.decode(encoding="UTF-8")
            .strip()
            .replace("\n", " ")
        )
        print(
            f"Process returned success code {completed_process_object.returncode} and standard out: {output_string}"
        )
        # result_dict = json.loads(output_string)
        # print(f"Completed process results: {result_dict['results']}")
    except subprocess.CalledProcessError as exception_object:
        # print(f"Exception: {exception_object.cmd} returned {exception_object.stderr} with exit status {exception_object.returncode}")
        print(
            f"Exception: command returned {exception_object.output} with exit status {exception_object.returncode}"
        )
    except:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        print(f"Exception: {exception_type}")
        traceback_list = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        traceback_string = " ".join(traceback_list).replace("\n", "  |  ")
        print(f"Exception traceback for ipam-read API call  --->  {traceback_string}")


def requests_cert_retry():
    """
    Makes an API call which retries renewal process for any device certificate renewal jobs that failed the first time.
    """
    connection_args_object = ConnectionArgs()
    request_body = json.dumps({})
    url = "https://device-management.widgets.com/cert-retry"
    request_headers = {"Content-Type": "application/json"}
    try:
        response_object = requests.post(
            url,
            data=request_body,
            headers=request_headers,
            verify=connection_args_object.cert_auth_bundle,
            auth=requests.auth.HTTPBasicAuth(
                connection_args_object.service_account_username,
                connection_args_object.adn_vip_password,
            ),
        )
        response_object.raise_for_status()
    except:
        # print(f"Exception on job venafi_retry: {sys.exc_info()[0]}")
        print(f"Exception on job venafi_retry: {sys.exc_info()}")
        result_value = None
    else:
        # Optional 'else' conditional for code to be executed if the try clause succeeds.
        response_object.encoding = "UTF-8"
        # Example responses:
        # {"results":"retried certs DN: [\"\\\\VED\\\\Policy\\\\Certificates\\\\f5\\\\external\\\\digi\\\\sa\\\\sapextportalext.partnersonline.com\"]"}
        # {"results":"No output from create_retry."}
        print(
            f"venafi_retry job received response code {response_object.status_code} and text: {response_object.text}"
        )
        result_value = response_object.text
    return result_value


def curl_cert_retry():
    """
    Makes an API call which retries renewal process for any device certificate renewal jobs that failed the first time.
    """
    connection_args_object = ConnectionArgs()
    url_string = "https://device-management.widgets.com/cert-retry"
    command_list = [
        "curl",
        "-k",
        "-u",
        f"{connection_args_object.service_account_username}:{connection_args_object.adn_vip_password}",
        "-X",
        "POST",
        "-H",
        "Content-Type:application/json",
        url_string,
    ]
    command_string = " ".join(command_list)
    # Example responses:
    # {"results":"retried certs DN: [\"\\\\VED\\\\Policy\\\\Certificates\\\\f5\\\\external\\\\digi\\\\sa\\\\sapextportalext.partnersonline.com\"]"}
    # {"results":"No output from create_retry."}
    try:
        # completed_process_object = subprocess.run(command_list, capture_output=True)
        # If shell=True, on POSIX the executable argument specifies a replacement shell for the default /bin/sh.
        # completed_process_object = subprocess.run(command_string, shell=True, check=True, capture_output=True)
        completed_process_object = subprocess.run(
            command_string, shell=True, capture_output=True, executable="/bin/sh"
        )
        # completed_process_object = subprocess.run(command_string, shell=True, capture_output=True, executable='/bin/bash')
        # completed_process_object = subprocess.check_output("ls non_existent_file; exit 0", stderr=subprocess.STDOUT, shell=True)

        # If returncode attribute is non-zero, check_returncode() raises a CalledProcessError.
        completed_process_object.check_returncode()
        # print(f"Completed process: {completed_process_object.args}")
        # print(f"Completed process returncode: {completed_process_object.returncode}")
        # print(f"Completed process standard out is: {completed_process_object.stdout}")
        output_string = (
            completed_process_object.stdout.decode(encoding="UTF-8")
            .strip()
            .replace("\n", " ")
        )
        print(
            f"Process returned success code {completed_process_object.returncode} and standard out: {output_string}"
        )
        # result_dict = json.loads(output_string)
        # print(f"Completed process results: {result_dict['results']}")
    except subprocess.CalledProcessError as exception_object:
        # print(f"Exception: {exception_object.cmd} returned {exception_object.stderr} with exit status {exception_object.returncode}")
        print(
            f"Exception: command returned {exception_object.output} with exit status {exception_object.returncode}"
        )
    except:
        exception_type, exception_value, exception_traceback = sys.exc_info()
        print(f"Exception: {exception_type}")
        traceback_list = traceback.format_exception(
            exception_type, exception_value, exception_traceback
        )
        traceback_string = " ".join(traceback_list).replace("\n", "  |  ")
        print(f"Exception traceback for ipam-read API call  --->  {traceback_string}")


if __name__ == "__main__":
    requests_cert_retry()
