# scheduled-jobs-app

Scheduled jobs app that runs in a Docker container with a minimal Flask app to answer health checks.

In real life this app runs in a container in a private cloud. Changes to its private git repo kick off a new push-to-deploy pipeline which is configured in a yaml file formatted to be read by a pipeline automation framework; those details have been removed from this version.
