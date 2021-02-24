import subprocess
import sys
import json
import argparse

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests


def get_query(owner, repo):
    q = """
            {
              Alerts: repository(name:"%s", owner:"%s") {
                vulnerabilityAlerts(first:100) {
                    nodes {
                        vulnerableManifestPath
                        securityVulnerability {
                            severity
                            vulnerableVersionRange
                            updatedAt
                            firstPatchedVersion{
                              identifier
                            }
                            package {
                                name
                            }
                            advisory {
                                summary
                                description
                            } 
                        }
                    }
                }
              } 
            }
            """ % (repo, owner)

    return q


def run_query(query, token):  # A simple function to use requests.post to make the API call. Note the json= section.
    headers = {"Authorization": f"token {token}"}
    request = requests.post('https://api.github.com/graphql', json={'query': query}, headers=headers)
    if request.status_code == 200:
        return request.json()
    else:
        print("Error: Query failed to run by returning code of {}.".format(request.status_code))
        exit()


def get_dependabot_data(query, token, output_file_path="Vulnerabilities.json"):
    response = run_query(query, token)
    # build new dict
    if 'errors' in response.keys():
        print("Error: " + response['errors'][0]['message'])
        exit()

    alerts = {'VulnerableFiles': {}}
    for node in response['data']['Alerts']['vulnerabilityAlerts']['nodes']:
        new_vulnerability = {node['securityVulnerability']['package']['name']: {
            'file': node['vulnerableManifestPath'],
            'severity': node['securityVulnerability']['severity'],
            'vulnerableVersionRange': node['securityVulnerability']['vulnerableVersionRange'],
            'patchedVersion': node['securityVulnerability']['firstPatchedVersion']['identifier'],
            'updatedAt': node['securityVulnerability']['updatedAt'],
            'summary': node['securityVulnerability']['advisory']['summary'],
            'advisory': node['securityVulnerability']['advisory']['description']
        }}
        alerts['VulnerableFiles'].update(new_vulnerability)

    with open(output_file_path, 'w') as f:
        json.dump(alerts, f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("owner", nargs="?", default=None)
    parser.add_argument("repository", nargs="?", default=None)
    parser.add_argument("github_token", nargs="?", default=None)
    parser.add_argument('-o', '--out-file')

    var_dict = vars(parser.parse_args())
    github_token = var_dict['github_token']

    graphql_query = get_query(var_dict['owner'], var_dict['repository'])

    if var_dict['out_file']:
        get_dependabot_data(graphql_query, github_token, var_dict['out_file'])
    else:
        get_dependabot_data(graphql_query, github_token)


if __name__ == '__main__':
    main()
