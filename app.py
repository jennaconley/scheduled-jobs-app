#!/usr/bin/env python3
from flask import Flask, redirect, request, render_template, session, flash, json, jsonify, send_from_directory
import requests
import logging
import json
import time
from datetime import datetime, date, timedelta
import sys
import os
from multiprocessing import Process, Value
import yaml
from apscheduler.schedulers.blocking import BlockingScheduler
import pynetbox
import pytz
import urllib3
from f5jobs import create_f5_remote_backups
from certjobs import requests_cert_retry, renew_device_certs

# Set logging level
logging.basicConfig(level=logging.INFO)
# logging.basicConfig(level=logging.DEBUG)

# Create the Flask app object:
app = Flask(__name__)
# Get secrets
platform_secret_dict = yaml.safe_load(open("/platform/secret/secret.yml"))
# Setting a secret key is required to use Flask sessions and the debug toolbar
app.secret_key = platform_secret_dict["SECRET_KEY"]

def convert_central_to_utc(hour_central_time, minute_central_time, function_name):
    """
    Convert US/Central time to UTC (Use 24-hour clock - no am/pm)
    """
    current_datetime_object = datetime.today()
    job_time_no_timezone_datetime_object = datetime(current_datetime_object.year,
                                    current_datetime_object.month,
                                    (current_datetime_object.day),
                                    hour_central_time,
                                    minute_central_time,
    )
    # The .localize() method takes a naive Datetime object, which has no timezone 
    # information, and interprets it as if it is in that Timezone object's timezone.
    timezone_object_central_time = pytz.timezone('US/Central')
    job_central_datetime_object = timezone_object_central_time.localize(job_time_no_timezone_datetime_object)

    # Once the naive Datetime object has been given an initial 
    # timezone (Central Time), it now has the capacity to change timezones. 
    # The .normalize() method can be used to move the job-time
    # Datetime Object to a new timezone (Central Time --> UTC). 
    utc_timezone_object = pytz.timezone('UTC')
    job_utc_datetime_object = utc_timezone_object.normalize(job_central_datetime_object)

    # Log conversion details and return UTC-converted job time as a Datetime Object
    central_string = job_central_datetime_object.strftime("%H:%M on %m/%d/%Y")
    utc_string = job_utc_datetime_object.strftime("%H:%M on %m/%d/%Y")
    print(f"Preparing to schedule {function_name} to run at {central_string} Central Time (UTC {utc_string}). ")
    return(job_utc_datetime_object)


def run_scheduled_jobs():
    """
    Gets times to run jobs from a config file, converts to UTC,
    and schedules them using the APScheduler library.
    """
    # Create an APScheduler object
    scheduler_object = BlockingScheduler()

    # Get job times from a config file that can be modified via an applications platform GUI.
    job_schedule_dict = yaml.safe_load(open("/platform/config/schedule.yml"))

    # Use a list of functions to access corresponding keys in the config file.
    list_of_functions = [create_f5_remote_backups, requests_cert_retry, renew_device_certs]

    for job_function in list_of_functions:
        hour_string, minute_string = job_schedule_dict[job_function.__name__].split(":")
        job_hour_central_time = int(hour_string)
        job_minute_central_time = int(minute_string)
        # Convert US/Central time to UTC (use 24-hour clock - NOT am/pm)
        job_utc_datetime_object = convert_central_to_utc(job_hour_central_time,
                                                        job_minute_central_time,
                                                        job_function.__name__,
        )
        # Add job to the scheduler object
        scheduler_object.add_job(job_function,
                                'cron',
                                hour=job_utc_datetime_object.hour,
                                minute=job_utc_datetime_object.minute,
                                timezone=pytz.utc,
        )
    # Start the scheduler after all jobs have been added
    scheduler_object.start()


@app.route("/", methods=["GET"])
def hello():
    return("Hello!")

@app.route("/health", methods=["GET"])
def health_check():
    """
    Flask route to answer required platform health check.
    """
    return("I'm healthy!")


if __name__ == "__main__":
    app.logger.info("Creating a seperate process to run scheduled jobs.")
    process_object = Process(target=run_scheduled_jobs)
    process_object.start()

    # Starting up a Flask server to reply to the platform health check.
    # IP address will be assigned by the applications platform.
    app.run(debug=False, use_reloader=False, port=8080, host="0.0.0.0")
