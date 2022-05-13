import argparse
import json
import os

#import pymsteams
import urllib3
from tld import get_fld
from tld import exceptions
import requests
import semver
# import networkx as nx


class BColors:
    HEADER = '\033[40m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Will be populated in runtime
DOMAINS_GLOBAL = {
}
DEPS = {}
FINDINGS = {}
DEPRECATED = {}
CHECKED_DOMAINS = []


# Not decided yet if I need to build graph to represent dependency tree but anyway:
# g = nx.Graph()


def get_npm_package_info(name, version=None):
    NPM_URL_PACKAGE = 'https://registry.npmjs.com/{}/{}'
    try:
        semver.parse(version)
    except ValueError as e:
        NPM_URL_PACKAGE = 'https://registry.npmjs.com/{}'

    response = requests.get(NPM_URL_PACKAGE.format(name, version), headers={
        'Accept': 'application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*'}, verify=False)
    parsed_json = {}
    try:
        parsed_json = response.json()
    finally:
        return parsed_json


def get_maintainers(package_info):
    #
    maintainers = []
    fields_of_interest = ['author', '_npmUser', 'maintainers']
    if 'versions' in package_info:
        for version in package_info['versions']:
            for field in fields_of_interest:
                if field in package_info:
                    maintainers.append(package_info[version][field])
    else:
        for field in fields_of_interest:
            if field in package_info:
                maintainers.append(package_info[field])
    return maintainers


# Actors contain various actors like 'author', '_npmUser', 'maintainers', so we iterate over them
def extract_emails(actors):
    emails = []

    for actor in actors:
        if type(actor) == list:
            for user in actor:
                if 'email' in user:
                    emails.append(user['email'])
        else:
            if 'email' in actor:
                emails.append(actor['email'])

    return emails


def extract_domains(emails):
    domains = []
    for email in emails:
        email = email.lower()
        domain = email[email.find('@') + 1:]
        if domain in DOMAINS_GLOBAL:
            if email not in DOMAINS_GLOBAL[domain]:
                DOMAINS_GLOBAL[domain].append(email)
        else:
            DOMAINS_GLOBAL[domain] = [email]
            if domain not in get_restricted_domains():
                domains.append(domain)
    return domains


# Skip scanning for domains returned by this function
def get_restricted_domains():
    # We are looking for custom domains so filtering well known services
    domains_to_filter = ['gmail.com', 'microsoft.com', 'google.com', 'outlook.com']
    return domains_to_filter


def get_dependencies(package_data):
    # fields_of_interest = ['dependencies', 'devDependencies']
    fields_of_interest = ['dependencies']
    list_of_dependencies = []
    for field in fields_of_interest:
        if field in package_data:
            for item in list(package_data[field].items()):
                if item not in list_of_dependencies:
                    list_of_dependencies.append(item)
    return list_of_dependencies


def check_domain_for_availability(domain):
    base_domain = get_fld(domain, fix_protocol=True)
    url = f'https://secure.domain.com/register/pages/dom_lookup_json.cmp?autoAdd=false&search_type=standard&dom_lookup={base_domain}'
    domain_status = requests.get(url, verify=False).json()
    is_available_for_purchase = 0
    for offer in domain_status:
        if offer['domain'] == base_domain:
            is_available_for_purchase = offer['availability']
            if is_available_for_purchase:
                print(f'    {BColors.OKBLUE} {domain} {BColors.OKGREEN}is available {BColors.ENDC}')
                #report_to_teams('We found something!!!', f'You should try to purchase the following domain: {domain}')
                FINDINGS[base_domain] = domain
            else:
                print(f'    {BColors.HEADER} {domain} already taken {BColors.ENDC}')
            break
    CHECKED_DOMAINS.append(domain)
    return is_available_for_purchase


def get_available_domains(domains):
    result = []
    for domain in domains:
        analyze_domain(domain)
        if check_domain_for_availability(domain):
            result.append(domain)
    return result


def get_domains_from_package_data(package_data):
    maintainers = get_maintainers(package_data)
    emails = extract_emails(maintainers)
    domains_for_checking = extract_domains(emails)
    return domains_for_checking


def get_domains_from_package(package, version):
    package_data = get_npm_package_info(package, version)
    maintainers = get_maintainers(package_data)
    emails = extract_emails(maintainers)
    domains_for_checking = extract_domains(emails)
    return domains_for_checking


def analyze_domain(domain):
    bad_root = ['ru', 'ua']
    try:
        fld = get_fld(domain, fix_protocol=True)
        parts = fld.split('.')
        if parts[1] in bad_root:
            #report_to_teams('Warning! Dangerous domain name!', domain)
            print(
                f'    {BColors.WARNING}Warning! Dangerous domain name: {parts[0]}.{BColors.FAIL}{parts[1]}{BColors.ENDC}')
    except exceptions.TldDomainNotFound as e:
        #report_to_teams('Oh no!', e)


def report_to_teams(title, message):
    teamshook = '<URL GOES HERE>'
    my_teams_message = pymsteams.connectorcard(teamshook)
    my_teams_message.title(title)
    my_message_section = pymsteams.cardsection()
    my_teams_message.addSection(my_message_section)
    my_teams_message.text(message)
    try:
        my_teams_message.send()
    except pymsteams.TeamsWebhookException:
        print('Something went wrong:(')


# TODO: Nice to have it
def build_graph(package, version):
    package_data = get_npm_package_info(package, version)
    dependencies = get_dependencies(package_data)
    for dependency in dependencies:
        package_data = get_npm_package_info(dependency[0], dependency[1])
        # g.add_edge(package_data, dependency, weight=1)
        build_graph(dependency[0], dependency[1])


def scan_packages_deep(package, version, depth):
    if depth <= 0:
        return []

    package_data = get_npm_package_info(package, version)
    print(f'{BColors.BOLD}{package} {version}:{BColors.ENDC}')

    dependencies = []
    this_domains = []

    if 'versions' in package_data:
        for ver in package_data['versions']:
            # g.add_edge((package_data['name'], version), (package_data['versions'][ver]['name'], ver), weight=depth)
            dependencies = dependencies + get_dependencies(package_data['versions'][ver])
            if 'deprecated' in package_data['versions'][ver]:
                DEPRECATED[(package, ver)] = package_data['versions'][ver]['deprecated']
    else:
        if '_id' in package_data:
            if package_data['_id'] in DEPS.keys():
                return []
            this_domains = get_domains_from_package_data(package_data)
            get_available_domains(this_domains)
            dependencies = get_dependencies(package_data)
            DEPS[package_data['_id']] = dependencies

    for dependency in set(dependencies):
        # g.add_edge((package, version), dependency, weight=depth)
        # print(f'Depth: {depth}/{package}:{version}: {dependency[0]}:{dependency[1]}')
        this_domains = this_domains + scan_packages_deep(dependency[0], dependency[1].strip('>=^~'),
                                                         depth - 1)
    return this_domains


def package_dissector(package):
    if package.get('dependencies'):
        print(f'{BColors.OKCYAN} {package["name"]} {BColors.ENDC}')
        for dep in package['dependencies']:
            scan_packages_deep(dep, package['dependencies'][dep], depth=int(args.depth))


def scan_single_package(package, version):
    domains_for_checking = get_domains_from_package(package, version)
    return get_available_domains(domains_for_checking)


def load_raw_domains(path):
    with open(path, 'r') as f:
        domains = list(f)
    return domains


def write_fld(path, data):
    with open(path, 'w', encoding='utf-8', ) as f:
        for domain in data:
            f.write(domain + '\n')


if __name__ == '__main__':
    # The idea behind this scanner is a composition of two assumptions:
    # 1. Some package maintainers are using custom email server hosted on their own domain
    # 2. This domain is expired and may be available for purchase currently
    print(str('''                                                                
    ██████   █████   ██████ ██   ██  █████   ██████  ███████ ███████     ██   ██ ██    ██ ███    ██ ████████ ███████ ██████  
    ██   ██ ██   ██ ██      ██  ██  ██   ██ ██       ██      ██          ██   ██ ██    ██ ████   ██    ██    ██      ██   ██ 
    ██████  ███████ ██      █████   ███████ ██   ███ █████   ███████     ███████ ██    ██ ██ ██  ██    ██    █████   ██████  
    ██      ██   ██ ██      ██  ██  ██   ██ ██    ██ ██           ██     ██   ██ ██    ██ ██  ██ ██    ██    ██      ██   ██ 
    ██      ██   ██  ██████ ██   ██ ██   ██  ██████  ███████ ███████     ██   ██  ██████  ██   ████    ██    ███████ ██   ██ 
                                                                                                                                                                                                        
    '''))
    parser = argparse.ArgumentParser(description='Explore who maintains the dependencies you are using')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', '--pkg', dest='package', help='Package in name:version format')
    group.add_argument('-f', '--file', dest='file', help='package.json file')
    group.add_argument('-fb', '--from-bitbucket', dest='bitbucket', help='Get packages from bitbucket', required=False,
                       action='store_true')
    parser.add_argument('-d', '--depth', dest='depth', help='Scanning depth', default=100)
    parser.add_argument('-Pa', '--proxyall', help='Everything will be passed through proxy', required=False,
                        action='store_true')

    # parser.add_argument('-s', '--silent', dest='silent', nargs=0, help='Passive scanning without domains resolving')
    # parser.add_argument('-E', '--ext', dest='file', nargs=0, help='Extended scanning with packages in name:version format')

    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.proxyall:
        os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8080'
        os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8080'

    if args.package:
        package = args.package.split(sep=':')
        result = scan_single_package(package[0], package[1])
        print(result)
        exit(0)

    elif args.file:
        with open('package.json', 'r', encoding='utf-8') as f:
            packages = json.load(f)
            package_dissector(packages)
    elif args.bitbucket:
        bitbucket_token = '<BITBUCKET_TOKEN>'
        bitbucket_url = '<BITBUCKET_URL>'
        data = '{"query":"package.json","entities":{"code":{}},"limits":{"primary":800,"secondary":1000}}'
        bitbucket_repos = requests.post(f'{bitbucket_url}/rest/search/latest/search',
                                        data=data,
                                        headers={'Authorization': f'Bearer {bitbucket_token}',
                                                 'Content-Type': 'application/json'}).json()
        for repo in bitbucket_repos['code']['values']:
            slug = repo['repository']['slug']
            project = repo['repository']['project']['key']
            #report_to_teams('Current:', f'{project}/repos/{slug}')
            package = requests.get(f'{bitbucket_url}/projects/{project}/repos/{slug}/raw/package.json',
                                   headers={'Authorization': f'Bearer {bitbucket_token}',
                                            'Content-Type': 'application/json'}).json()
            package_dissector(package)
    exit(0)
    # print('\nFinally, we are finished. Lets check what we found:\n')
    # if len(FINDINGS) == 0:
    #     print(f'{BColors.FAIL}Nothing!{BColors.ENDC}')
    # else:
    #     for domain in FINDINGS:
    #         print(f'{BColors.BOLD}{domain}{BColors.OKGREEN} is available for purchase{BColors.ENDC}')
    #         if domain in DOMAINS_GLOBAL:
    #             print(f'Mailserver on this domain contains following emails: {DOMAINS_GLOBAL[domain]}')
    # print(DOMAINS_GLOBAL)
