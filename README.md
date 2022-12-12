> :warning: **This Webhook Connector can use only Incident Stream for now**:

# Installation steps

## OpenCTI Platform

1. Create a new account with the builtin `Connector` role
    - Use a random password
    - Keep its API token next to you
2. Go to Data > Data sharing > '+' sign
    - Name your stream like "Webhook Incident Connector" for example
    - Choose `Entity Type: Incident` as filter
    - Create! and preserve the new Stream ID

## Edit the Docker-compose options

| Option                                | Description                                                                           | Mandatory |
|---------------------------------------|---------------------------------------------------------------------------------------|-----------|
| OPENCTI_URL                           | The URL of the OpenCTI platform.                                                      | Yes       |
| OPENCTI_TOKEN                         | From the newly created account                                                        | Yes       |
| OPENCTI_JSON_LOGGING                  | Enable or not the log format as JSON                                                  | No        |
| CONNECTOR_ID                          | UUIv4 of this connector, it must be unique                                            | Yes       |
| CONNECTOR_TYPE                        | Must be STREAM (this is the connector type).                                          | Yes       |
| CONNECTOR_LIVE_STREAM_ID              | From the newly created Incident Stream (See installation steps)                       | Yes       |
| CONNECTOR_LIVE_STREAM_WITH_INFERENCES | Fetch incident from the rules engine                                                  | Yes       |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE   | Fetch delete events                                                                   | Yes       |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | Fetch incident without any relations                                                  | Yes       |
| CONNECTOR_NAME                        | The name of this webhook connector instance                                           | Yes       |
| CONNECTOR_SCOPE                       | Must be `Incident`, not used in this connector                                        | Yes       |
| CONNECTOR_LOG_LEVEL                   | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). | No        |
| WEBHOOK_URL                           | Your endpoint URL where to send the alerts                                            | Yes       |
| WEBHOOK_USERNAME                      | Your username if the endpoint is protected by login                                   | No        |
| WEBHOOK_PASSWORD                      | Your password if the endpoint is protected by login                                   | No        |
| WEBHOOK_SSL_VERIFY                    | True/False or absolute path to a CA Bundle                                            | No        |
| WEBHOOK_LOG_EVENTS                    | True/False to log events and alerts for debug purpose                                 | No        |

## Start the connector 

```sh
$ docker-compose up --build -d
```
