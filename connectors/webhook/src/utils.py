from collections import defaultdict

def clean_graphql_response(data, output = None):
    if output is None: output = {}
    for key, value in data.items():
        if isinstance(value, dict) and "edges" in value.keys():
            output[key] = list(
                map(
                    lambda x: clean_graphql_response(x["node"], {}), 
                    value["edges"]
                )
            )
        elif isinstance(value, dict):
            output[key] = {}
            clean_graphql_response(value, output[key])
        else:
            output[key] = value
    return output

def get_statuses(domains, groupby: str = "id"):
    if not groupby in ["id", "name"]: return "Bad groupby: id or name"
    statuses = defaultdict(lambda: defaultdict(dict))
    for domain in domains:
        for status in domain["statuses"]:
            s_id = status["id"]
            s_name = status["template"]["name"]
            if groupby == "id":
                statuses[domain["label"]].update({s_id: s_name})
            elif groupby == "name":
                statuses[domain["label"]].update({s_name: s_id})
    return statuses

workflow_id_query = """
    query WorkflowLinesQuery {
    ...WorkflowLines_data
    }

    fragment WorkflowLines_data on Query {
    settings {
        id
        platform_enable_reference
    }
    subTypes {
        edges {
        node {
            id
            label
            workflowEnabled
            statuses {
            edges {
                node {
                id
                order
                template {
                    name
                    color
                    id
                }
                }
            }
            }
        }
        }
    }
    }
"""

queries = {
    "get_statuses": workflow_id_query
}
