import requests
import csv
import os

GITHUB_API_URL = "https://api.github.com/graphql"
GITHUB_REST_URL = "https://api.github.com"
access_token = "os.getenv('INPUT_GITHUB_TOKEN')"
enterprise_name = os.getenv('INPUT_ENTERPRISE_NAME')

HEADERS = {
    'Accept': 'application/vnd.github+json',
    'Authorization': f'token {access_token}',
    'X-GitHub-Api-Version': '2022-11-28'
}

def run_query(query, variables=None):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(GITHUB_API_URL, json={'query': query, 'variables': variables}, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Query failed to run with status code {response.status_code}. {response.json()}")

def get_organizations(enterprise_name):
    query = """
    query($cursor: String, $enterprise_name: String!) {
      enterprise(slug: $enterprise_name) {
        organizations(first: 100, after: $cursor) {
          edges {
            node {
              login
            }
          }
          pageInfo {
            endCursor
            hasNextPage
          }
        }
      }
    }
    """
    organizations = []
    variables = {"cursor": None, "enterprise_name": enterprise_name}

    while True:
        result = run_query(query, variables)
        orgs = result['data']['enterprise']['organizations']['edges']
        for org in orgs:
            organizations.append(org['node']['login'])
            print(org['node']['login'])
        page_info = result['data']['enterprise']['organizations']['pageInfo']
        if not page_info['hasNextPage']:
            break
        variables['cursor'] = page_info['endCursor']

    return organizations

def get_paginated_alerts_count(url):
    alerts_count = 0
    while url:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            alerts_count += len(response.json())
            # Check for pagination
            url = None
            if 'Link' in response.headers:
                links = response.headers['Link'].split(',')
                for link in links:
                    if 'rel="next"' in link:
                        url = link[link.find('<') + 1:link.find('>')]
                        break
        else:
            url = None
    return alerts_count

def get_alerts_count(org_name, severity):
    alerts = {
        'code_scanning': 0,
        'secret_scanning': 0,
        'dependabot': 0
    }

    # Code Scanning Alerts
    code_scanning_url = f'{GITHUB_REST_URL}/orgs/{org_name}/code-scanning/alerts?state=open&severity={severity}'
    alerts['code_scanning'] = get_paginated_alerts_count(code_scanning_url)

    # Secret Scanning Alerts
    secret_scanning_url = f'{GITHUB_REST_URL}/orgs/{org_name}/secret-scanning/alerts?state=open&severity={severity}'
    alerts['secret_scanning'] = get_paginated_alerts_count(secret_scanning_url)

    # Dependabot Alerts
    dependabot_url = f'{GITHUB_REST_URL}/orgs/{org_name}/dependabot/alerts?state=open&severity={severity}'
    alerts['dependabot'] = get_paginated_alerts_count(dependabot_url)

    return alerts

def get_user_email(username):
    url = f'{GITHUB_REST_URL}/users/{username}'
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        user_data = response.json()
        return user_data.get('email', 'N/A')
    return 'N/A'

def get_org_owners(org_name):
    url = f'{GITHUB_REST_URL}/orgs/{org_name}/members?role=admin'
    response = requests.get(url, headers=HEADERS)
    owners = []
    if response.status_code == 200:
        admins = response.json()
        for admin in admins:
            email = get_user_email(admin['login'])
            owners.append(f"{admin['login']} ({email})")
    return ', '.join(owners) if owners else 'N/A'

def write_alerts_to_csv(org_names):
    with open('github_alerts-with-owners.csv', 'w', newline='') as csvfile:
        fieldnames = ['organization', 'severity', 'code_scanning', 'secret_scanning', 'dependabot', 'owners']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for severity in ['high', 'critical']:
            for org in org_names:
                print(f"Processing org: {org} with severity: {severity}")
                alerts = get_alerts_count(org, severity)
                owners = get_org_owners(org)
                print(alerts)
                writer.writerow({
                    'organization': org,
                    'severity': severity,
                    'code_scanning': alerts['code_scanning'],
                    'secret_scanning': alerts['secret_scanning'],
                    'dependabot': alerts['dependabot'],
                    'owners': owners
                })

org_names = get_organizations(enterprise_name)
write_alerts_to_csv(org_names)
