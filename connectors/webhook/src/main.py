from pathlib import Path
import traceback
import yaml
import time
import json
import requests
import logging
import re

from pycti import OpenCTIConnectorHelper, get_config_variable
from utils import (
    clean_graphql_response,
    get_statuses,
    queries
)

home = Path(__file__).resolve().parent
(home / "logs").mkdir(parents=True, exist_ok=True)

events_id_treated = set()

class Webhook:
    def __init__(self):
        config_file_path = home / "config.yml"
        config = (
            yaml.load(config_file_path.open(), Loader=yaml.FullLoader)
            if config_file_path.exists() and config_file_path.is_file()
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.webhook_url = get_config_variable(
            "WEBHOOK_URL", ["webhook", "url"], config
        )
        self.webhook_username = get_config_variable(
            "WEBHOOK_USERNAME", ["webhook", "username"], config
        )
        self.webhook_password = get_config_variable(
            "WEBHOOK_PASSWORD", ["webhook", "password"], config
        )
        self.webhook_ssl_verify = get_config_variable(
            "WEBHOOK_SSL_VERIFY", ["webhook", "ssl_verify"], config
        )
        self.webhook_log_events = get_config_variable(
            "WEBHOOK_LOG_EVENTS", ["webhook", "log_events"], config
        )

        resp = clean_graphql_response(
            self.helper.api.query(
                queries.get("get_statuses")
            )
        )
        self.statuses = get_statuses(resp["data"]["subTypes"], groupby="id")

        self.helper.api.indicator.properties = re.sub(
            r"pattern_version\n(\s+)",
            r"pattern_version\n\1status {\n\1 id\n\1}\n\1creator {\n\1 name\n\1}\n\1",
            self.helper.api.indicator.properties
        )

    def _process_message(self, msg):
        time_now = time.strftime("%Y_%m_%d_%H%M%S")
        try:
            event = json.loads(msg.data)

            if self.webhook_log_events:
                event_log = home / "logs" / f"event_{time_now}.json"
                
                with event_log.open(mode="a") as evfile:
                    evfile.write(json.dumps(event, ensure_ascii=False) + "\n")
            
            if not event["data"]["id"].startswith("incident--"):
                return

            # Extract incident ID and its status from SDO extension
            ext_key = list(event["data"]["extensions"])[0]
            ext_path = event["data"]["extensions"][ext_key]
            incident_id = ext_path["id"]
            incident_status = self.statuses["Incident"].get(ext_path["workflow_id"], "UNKNOWN")

            if event["type"] == "delete" and not event["data"]["id"] in events_id_treated:
                body = {
                    "message": event["message"],
                    "action": "delete",
                    "incident_id": incident_id
                }

                r = requests.post(
                    self.webhook_url,
                    json=body,
                    auth=(self.webhook_username, self.webhook_password),
                    verify=self.webhook_ssl_verify,
                    timeout=20
                )
                if not r.ok:
                    logging.error(f"alert wasn't sent successfully", extra = {
                        "status_code": r.status_code,
                        "text": r.text,
                        "body": json.dumps(body),
                    })

                    return
                
                else:
                    events_id_treated.add(event["data"]["id"])
                    logging.info(
                        "event deleted",
                        extra = {
                            "event_id": event["data"]["id"],
                            "incident_id": incident_id
                        }
                    )

                    return


            elif incident_status!="NEW" or ext_path["is_inferred"] == False:
                # Do not handle manual incident because of it doesn't contains any relations (no indicator, observable, etc)
                logging.info(
                    "incident skipped", 
                    extra = {
                        "title": event["data"]["name"], 
                        "status": incident_status, 
                        "is_inferred": ext_path["is_inferred"]
                    }
                )
                return

            logging.info("incoming incident", extra={"title": event["data"]["name"]})

            # Fetch indicator details via relationship
            # and associate the corresponding observed data to the observable
            relations = self.helper.api.stix_core_relationship.list(
                elementId=incident_id,
                relationship_type="related-to"
            )
            relation = next(iter(relations), {})
            indicator_id = relation["to"]["id"]
            indicator = self.helper.api.indicator.read(id=indicator_id)
            indicator_status_id = indicator["status"]["id"]
            indicator_hits = 0
            for obs in indicator.get("observables", []):
                observed_data = next(
                    iter(self.helper.api.stix_cyber_observable.observed_data(id=obs["id"])),
                    False
                )
                if observed_data:
                    obs.update({
                        "first_observed": observed_data["first_observed"],
                        "last_observed": observed_data["last_observed"],
                        "number_observed": observed_data["number_observed"]
                    })

                    indicator_hits += observed_data["number_observed"]

                obs["value"] = obs.pop("observable_value")


            # Fetch indicating Tool, organization, .. to the indicator
            indicates = self.helper.api.stix_core_relationship.list(
                elementId=indicator_id,
                relationship_type="indicates"
            )
            indicates = list(
                map(
                    lambda rel: {"entity_type": rel["to"]["entity_type"], "value": rel["to"]["name"]},
                    indicates
                )
            )

            # Fetch linked reports
            reports = self.helper.api.report.list(
                filters=[{"key": "objectContains", "values": [indicator_id]}],
                first=8, orderBy="published", orderMode="desc"
            )
            reports = list(
                map(
                    lambda rep: {"id": rep["id"], "name": rep["name"], "description": rep["description"]},
                    reports
                )
            )

            alert = {
                "action": "create",
                "id": incident_id,
                "status": incident_status,
                "status_id": ext_path["workflow_id"],
                "created": event["data"]["created"],
                "modified": event["data"]["modified"],
                "revoked": event["data"]["revoked"],
                "confidence": event["data"]["confidence"],
                "name": event["data"]["name"],
                "description": event["data"]["description"],
                "first_seen": event["data"]["first_seen"],
                "last_seen": event["data"]["last_seen"],
                "indicator_id": indicator["id"],
                "indicator_name": indicator["name"],
                "indicator_status": self.statuses["Indicator"].get(indicator_status_id, "UNKNOWN"),
                "indicator_status_id": indicator_status_id,
                "indicator_valid_from": indicator["valid_from"],
                "indicator_valid_until": indicator["valid_until"],
                "indicator_creator_name": indicator["creator"]["name"],
                "indicator_opencti_detection": indicator["x_opencti_detection"],
                "indicator_opencti_score": indicator["x_opencti_score"],
                "indicator_opencti_main_observable_type": indicator["x_opencti_main_observable_type"],
                "indicator_hits": indicator_hits,
                "observables": indicator["observables"],
                "indicates": indicates,
                "reports": reports,
            }

            if self.webhook_log_events:
                alert_log = home / "logs" / f"alert_{time_now}.json"
                
                with alert_log.open(mode="a") as file:
                    file.write(json.dumps(alert, ensure_ascii=False) + "\n")

            r = requests.post(
                self.webhook_url,
                json=alert,
                auth=(self.webhook_username, self.webhook_password),
                verify=self.webhook_ssl_verify,
                timeout=20
            )
            if not r.ok:
                logging.error(f"alert wasn't sent successfully", extra = {
                    "status_code": r.status_code,
                    "text": r.text,
                    "alert": json.dumps(alert),
                    "event": msg
                })

            logging.info("sending new incident", extra = {"incident": alert["name"]})

        except json.JSONDecodeError as error:
            logging.error(f"JSON Decoder error", extra = {"error": error, "event": msg})

        except requests.exceptions.Timeout:
            logging.error(
                f"sending webhook has timed out",
                extra = {
                    "url": self.webhook_url,
                    "incident_id": incident_id
                }
            )

        except Exception as error:
            logging.error(
                f"unexpected erorr was occured",
                extra = {
                    "error": error,
                    "traceback": traceback.format_exc()
                }
            )

    def start(self):
        self.helper.listen_stream(self._process_message)

if __name__ == "__main__":
    try:
        connector = Webhook()
        connector.start()
    except Exception as e:
        logging.error("Error unexpected", exc_info=True)
        time.sleep(10)
