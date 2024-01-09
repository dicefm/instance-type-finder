#!/usr/bin/env python3
import os
import json
import time
import boto3
import logging
import argparse
import subprocess
from tabulate import tabulate
from pkg_resources import resource_filename

CACHE_DIR = ".cache"
SPOTINFO_CACHE_FILE = os.path.join(CACHE_DIR, "spotinfo_cache.json")
AWS_INSTANCE_TYPES_CACHE_FILE = os.path.join(
    CACHE_DIR, "aws_instance_types_cache.json")
AWS_PRICING_CACHE_FILE = os.path.join(
    CACHE_DIR, "aws_prices_cache.json")
CACHE_VALIDITY = 24 * 60 * 60  # 24 hours in seconds

default_min_cpu = 1
default_max_cpu = 999
default_min_memory = 0.1
default_max_memory = 10000
default_min_network = 0
default_max_network = 10000
max_pods_cap = 110

def run_shell_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=True, text=True)
    return result.stdout, result.returncode


def is_cache_valid(cache_file):
    if not os.path.exists(cache_file):
        logging.debug(f"{cache_file} does not exist")
        return False

    current_time = time.time()
    file_modification_time = os.path.getmtime(cache_file)
    elapsed_time = current_time - file_modification_time

    if elapsed_time <= CACHE_VALIDITY:
        logging.debug(f"{cache_file} is less than {CACHE_VALIDITY} seconds old @ {elapsed_time}")
        return True
    else:
        logging.debug(f"{cache_file} is older than {CACHE_VALIDITY} seconds old @ {elapsed_time}")

    return elapsed_time <= CACHE_VALIDITY


def get_spot_instance_info(region, refresh=False):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    if refresh or not is_cache_valid(SPOTINFO_CACHE_FILE):
        command = f"spotinfo --region={region} --output=json | tee {SPOTINFO_CACHE_FILE}"
        output, return_code = run_shell_command(command)
    else:
        with open(SPOTINFO_CACHE_FILE, "r") as file:
            output = file.read()
            return_code = 0

    return json.loads(output) if return_code == 0 else None


def get_aws_instance_types(region, refresh=False):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    if refresh or not is_cache_valid(AWS_INSTANCE_TYPES_CACHE_FILE):
        ec2_client = boto3.client("ec2", region_name=region)
        instances = []
        next_token = None

        while True:
            if next_token:
                response = ec2_client.describe_instance_types(
                    NextToken=next_token)
            else:
                response = ec2_client.describe_instance_types()

            instances.extend(response['InstanceTypes'])
            next_token = response.get('NextToken')

            if not next_token:
                break

        with open(AWS_INSTANCE_TYPES_CACHE_FILE, "w") as file:
            json.dump(instances, file)
    else:
        with open(AWS_INSTANCE_TYPES_CACHE_FILE, "r") as file:
            instances = json.load(file)

    return instances


# This function and the next based on https://stackoverflow.com/a/51685222/5738
def get_region_name(region_code):
    default_region = 'US East (N. Virginia)'
    endpoint_file = resource_filename('botocore', 'data/endpoints.json')
    try:
        with open(endpoint_file, 'r') as f:
            data = json.load(f)
        # Botocore is using Europe while Pricing API using EU...sigh...
        return data['partitions'][0]['regions'][region_code]['description'].replace('Europe', 'EU')
    except IOError:
        return default_region


def get_aws_prices(region, refresh=False):
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    if refresh or not is_cache_valid(AWS_PRICING_CACHE_FILE):
        client = boto3.client('pricing', region_name='us-east-1')
        price_list = []
        next_token = None

        while True:
            if next_token:
                response = client.get_products(
                    ServiceCode='AmazonEC2',
                    Filters=[
                        {"Field": 'location', "Value": get_region_name(
                            region), "Type": "TERM_MATCH"},
                        {"Field": 'tenancy', "Value": 'shared', "Type": "TERM_MATCH"},
                        {"Field": 'preInstalledSw',
                            "Value": 'NA', "Type": "TERM_MATCH"},
                        {"Field": 'capacitystatus',
                            "Value": 'Used', "Type": "TERM_MATCH"}
                    ],
                    NextToken=next_token
                )
            else:
                response = client.get_products(
                    ServiceCode='AmazonEC2',
                    Filters=[
                        {"Field": 'location', "Value": get_region_name(
                            region), "Type": "TERM_MATCH"},
                        {"Field": 'tenancy', "Value": 'shared', "Type": "TERM_MATCH"},
                        {"Field": 'preInstalledSw',
                            "Value": 'NA', "Type": "TERM_MATCH"},
                        {"Field": 'capacitystatus',
                            "Value": 'Used', "Type": "TERM_MATCH"}
                    ]
                )

            for item in response['PriceList']:
                price_list.append(json.loads(item))

            next_token = response.get('NextToken')

            if not next_token:
                break

        with open(AWS_PRICING_CACHE_FILE, "w") as file:
            json.dump(price_list, file)
    else:
        with open(AWS_PRICING_CACHE_FILE, "r") as file:
            price_list = json.load(file)

    return price_list


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Command line application to execute shell commands and query AWS API."
    )
    parser.add_argument(
        "--region",
        help="AWS region for spot instance info (default: eu-west-1)",
        default="eu-west-1"
    )
    parser.add_argument(
        "--refresh",
        help="Refresh cached data",
        action="store_true"
    )
    parser.add_argument(
        "--cpu",
        help="CPU value for instances",
        type=int
    )
    parser.add_argument(
        "--min-cpu",
        help=f"Minimum CPU value for instances (default: {default_min_cpu})",
        type=int
    )
    parser.add_argument(
        "--max-cpu",
        help=f"Maximum CPU value for instances (default: {default_max_cpu})",
        type=int
    )
    parser.add_argument(
        "--memory",
        help="Memory value for instances",
        type=float
    )
    parser.add_argument(
        "--min-memory",
        help=f"Memory value for instances (default: {default_min_memory})",
        type=float
    )
    parser.add_argument(
        "--max-memory",
        help=f"Memory value for instances (default: {default_max_memory})",
        type=float
    )
    parser.add_argument(
        "--network",
        help="Network throughput in Gb/s (excluding 'up to' value) for instances",
        type=float
    )
    parser.add_argument(
        "--min-network",
        help=f"Minimum network throughput in Gb/s (excluding 'up to' value) for instances (default: {default_min_network})",
        type=float
    )
    parser.add_argument(
        "--max-network",
        help=f"Maximum network throughput in Gb/s for instances (default: {default_max_network})",
        type=float
    )
    parser.add_argument(
        "--architecture",
        help="Architecture value for instances (default: x86_64)",
        default='x86_64'
    )
    parser.add_argument(
        "--hypervisor",
        help="Hypervisor value for instances (default: nitro)",
        default='nitro'
    )
    parser.add_argument(
        "--interruption-maximum",
        # These values determined by `grep '"max":' spotinfo_cache.json | sort | uniq`
        help="Maximum interruption value (default: 16 percent) Values are typically: 5 (rare), 11 (low), 16 (medium), 22 (high), 100 (likely) percent",
        type=int,
        default=16
    )
    parser.add_argument(
        "--debug",
        help="Output reasons for filtering out certain values, like 'Outside memory range' or 'Not available for spot workloads'",
        action="store_true"
    )
    parser.add_argument(
        "--verbose",
        help="Output the JSON values collected for all validated instance types. Prevents csv or table output.",
        action="store_true"
    )
    parser.add_argument(
        "--csv",
        help="Output the validated instance types in a CSV format.",
        action="store_true"
    )
    parser.add_argument(
        "--json",
        help="Output the validated instance types in JSON format.",
        action="store_true"
    )
    parser.add_argument(
        "--order-by-price",
        help="Changes the result ordering from the default of by-instance-name to by-spot-price.",
        action="store_true"
    )
    parser.add_argument(
        "--order-by-interruption",
        help="Changes the result ordering from the default of by-instance-name to by-risk-of-interruption.",
        action="store_true"
    )
    parser.add_argument(
        "--like",
        help="Set memory and cpu values to the same as another instance type."
    )
    args = parser.parse_args()
    return args


def main():
    min_memory = float(default_min_memory)
    max_memory = float(default_max_memory)
    min_cpu = float(default_min_cpu)
    max_cpu = float(default_max_cpu)
    min_network = float(default_min_network)
    max_network = float(default_max_network)

    instances = {}
    valid_instances = {}

    args = parse_arguments()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    aws_instance_types = get_aws_instance_types(args.region, args.refresh)
    spot_info = get_spot_instance_info(args.region, args.refresh)

    # Very heavy in terms of processing and loading data. Last check, this included over 4k items in JSON, unfiltered
    # Additional filtering is recommended if we want to use this to get the on-demand prices too.
    ##
    # At least the code is available if we want it!
    #
    # price_list = get_aws_prices(args.region, args.refresh)

    for instance in aws_instance_types:
        instances.update({instance['InstanceType']: instance})
    for instance in spot_info:
        if instance['Instance'] in instances:
            instances[instance['Instance']].update(instance)
        else:
            logging.debug(
                f'Missing instance type {instance["Instance"]} from AWS Instance Types... legacy?')

    if args.like is not None:
        if args.like in instances:
            instance = instances[args.like]
            if 'Info' in instance and 'ram_gb' in instance['Info']:
                min_memory = instance['Info']['ram_gb']
                max_memory = instance['Info']['ram_gb']
            if 'Info' in instance and 'cores' in instance['Info']:
                min_cpu = instance['Info']['cores']
                max_cpu = instance['Info']['cores']
            if 'x86_64' in instance.get('ProcessorInfo', {}).get('SupportedArchitectures', []):
                args.architecture = 'x86_64'
            elif 'arm64' in instance.get('ProcessorInfo', {}).get('SupportedArchitectures', []):
                args.architecture = 'arm64'
            elif 'arm64_mac' in instance.get('ProcessorInfo', {}).get('SupportedArchitectures', []):
                args.architecture = 'arm64_mac'
            elif 'x86_64_mac' in instance.get('ProcessorInfo', {}).get('SupportedArchitectures', []):
                args.architecture = 'x86_64_mac'
        else:
            logging.error(
                f"Instance type {args.like} provided for RAM and CPU comparison, however, this instance type was not located. Aborting.")
            exit(1)

    if args.min_memory is not None:
        min_memory = args.min_memory
    if args.max_memory is not None:
        max_memory = args.max_memory
    if args.memory is not None:
        min_memory = args.memory
        max_memory = args.memory

    if args.min_cpu is not None:
        min_cpu = args.min_cpu
    if args.max_cpu is not None:
        max_cpu = args.max_cpu
    if args.cpu is not None:
        min_cpu = args.cpu
        max_cpu = args.cpu

    if args.min_network is not None:
        min_network = args.min_network
    if args.max_network is not None:
        max_network = args.max_network
    if args.network is not None:
        min_network = args.network
        max_network = args.network

    logging.info('Search criteria:')
    logging.info(f'Memory      : >{min_memory} <{max_memory}')
    logging.info(f'CPU         : >{min_cpu} <{max_cpu}')
    logging.info(f'Network     : >{min_network} <{max_network}')
    logging.info(f'Architecture: {args.architecture}')
    logging.info(f'Hypervisor  : {args.hypervisor}')
    logging.info(f'Interruption: <{args.interruption_maximum}')

    for instance_id in instances:
        instance = instances[instance_id]
        valid_instance = True

        ######################################
        # Filter out unsuitable instance types
        ######################################
        if 'spot' not in instance['SupportedUsageClasses']:
            valid_instance = False
            logging.debug(
                f"Instance type {instance_id} is not eligable for Spot ('spot' was not in {instance['SupportedUsageClasses']})")

        if 'Info' not in instance:
            valid_instance = False
            logging.debug(
                f"Instance type {instance_id} does not have spot interruption data.")

        if args.architecture is not None:
            if 'ProcessorInfo' in instance and 'SupportedArchitectures' in instance['ProcessorInfo']:
                if args.architecture not in instance['ProcessorInfo']['SupportedArchitectures']:
                    valid_instance = False
                    logging.debug(
                        f"Instance type {instance_id} has an invalid architecture type ({args.architecture} was not in {instance['ProcessorInfo']['SupportedArchitectures']})")
                else:
                    logging.debug(
                        f"Instance type {instance_id} has a valid architecture type ({args.architecture} was in {instance['ProcessorInfo']['SupportedArchitectures']})")
            else:
                valid_instance = False
                logging.debug(
                    f"Instance type {instance_id} is missing critical data: instance['ProcessorInfo']['SupportedArchitectures'])")

        if args.hypervisor is not None:
            if 'Hypervisor' in instance:
                if args.hypervisor not in instance['Hypervisor']:
                    valid_instance = False
                    logging.debug(
                        f"Instance type {instance_id} has an invalid hypervisor type ({args.hypervisor} was not in {instance['Hypervisor']})")
                else:
                    logging.debug(
                        f"Instance type {instance_id} has a valid hypervisor type ({args.hypervisor} was in {instance['Hypervisor']})")
            else:
                valid_instance = False
                logging.debug(
                    f"Instance type {instance_id} is missing critical data: instance['Hypervisor'])")

        if 'Info' in instance and 'ram_gb' in instance['Info']:
            if instance['Info']['ram_gb'] < min_memory or instance['Info']['ram_gb'] > max_memory:
                valid_instance = False
                logging.debug(
                    f"Instance type {instance_id} has an invalid ram_gb ({instance['Info']['ram_gb']} was less than {min_memory} or greater than {max_memory})")
            else:
                logging.debug(
                    f"Instance type {instance_id} has a valid ram_gb ({instance['Info']['ram_gb']} was greater than {min_memory} or less than {max_memory})")
        else:
            valid_instance = False
            logging.debug(
                f"Instance type {instance_id} is missing critical data: instance['Info']['ram_gb'])")

        if 'Info' in instance and 'cores' in instance['Info']:
            if instance['Info']['cores'] < min_cpu or instance['Info']['cores'] > max_cpu:
                valid_instance = False
                logging.debug(
                    f"Instance type {instance_id} has an invalid number of cores ({instance['Info']['cores']} was less than {min_cpu} or greater than {max_cpu})")
            else:
                logging.debug(
                    f"Instance type {instance_id} has a valid number of cores ({instance['Info']['cores']} was greater than {min_cpu} or less than {max_cpu})")
        else:
            valid_instance = False
            logging.debug(
                f"Instance type {instance_id} is missing critical data: instance['Info']['cores'])")

        if 'NetworkInfo' in instance and 'NetworkPerformance' in instance['NetworkInfo']:
            if instance['NetworkInfo']['NetworkPerformance'] == '4x 100 Gigabit':
                instance['NetworkInfo']['NetworkPerformance'] = 400

            if (
                instance['NetworkInfo']['NetworkPerformance'] == 'High' or
                instance['NetworkInfo']['NetworkPerformance'] == 'Moderate' or
                instance['NetworkInfo']['NetworkPerformance'] == 'Low' or
                instance['NetworkInfo']['NetworkPerformance'] == 'Low to Moderate' or
                instance['NetworkInfo']['NetworkPerformance'] == 'Very Low'
            ):
                valid_instance = False
                logging.debug(
                    f"Instance type {instance_id} has an invalid network performance ({instance['NetworkInfo']['NetworkPerformance']} contained an unacceptable string.)")
            else:
                network_performance = float(str(instance['NetworkInfo']['NetworkPerformance']).replace('Up to ', '').replace('Gigabit', ''))
                min_network_performance = network_performance
                max_network_performance = network_performance
                assumed_network_performance = ""
                if str(instance['NetworkInfo']['NetworkPerformance']).startswith('Up to '):
                    min_network_performance = network_performance / 2 # Assume half network speed for min performance
                    max_network_performance = network_performance     # Assume actual network speed for max performance
                    assumed_network_performance = " assumed to be"
                if min_network_performance < min_network or max_network_performance > max_network:
                    valid_instance = False
                    logging.debug(
                        f"Instance type {instance_id} has an invalid level of network performance ({instance['NetworkInfo']['NetworkPerformance']} was{assumed_network_performance} less than {min_network} or greater than {max_network})")
                else:
                    logging.debug(
                        f"Instance type {instance_id} has a valid level of network performance ({instance['NetworkInfo']['NetworkPerformance']} was{assumed_network_performance} greater than {min_network} or less than {max_network})")
        else:
            valid_instance = False
            logging.debug(
                f"Instance type {instance_id} is missing critical data: instance['NetworkInfo']['NetworkPerformance'])")

        if args.interruption_maximum is not None:
            if 'Range' in instance and 'max' in instance['Range']:
                if instance['Range']['max'] > args.interruption_maximum:
                    valid_instance = False
                    logging.debug(
                        f"Instance type {instance_id} has an invalid interruption_maximum ({instance['Range']['max']} was greater than {args.interruption_maximum})")

        if valid_instance:
            ######################################
            # Add extra network info
            ######################################
            if 'NetworkInfo' in instance and 'NetworkPerformance' in instance['NetworkInfo']:
                max_interfaces = instance['NetworkInfo']['MaximumNetworkInterfaces']
                max_ips_per_interface = instance['NetworkInfo']['Ipv4AddressesPerInterface'] - 1
                theoretical_max_pods = (
                    max_interfaces * max_ips_per_interface) + 2
                max_pods = theoretical_max_pods if theoretical_max_pods < max_pods_cap else max_pods_cap

            if args.verbose:
                valid_instances[instance_id] = instance
            else:
                valid_instances[instance_id] = {
                    'InstanceType': instance_id,
                    'RAM': instance['Info']['ram_gb'] if 'Info' in instance and 'ram_gb' in instance['Info'] else 'N/A',
                    'vCPU': instance['Info']['cores'] if 'Info' in instance and 'cores' in instance['Info'] else 'N/A',
                    'Network': instance['NetworkInfo']['NetworkPerformance'] if 'NetworkInfo' in instance and 'NetworkPerformance' in instance['NetworkInfo'] else 'N/A',
                    'SpotPrice': instance['Price'],
                    'CappedMaxPods': max_pods,
                    'TheoreticalMaxPods': theoretical_max_pods,
                    'InterruptionRisk': instance['Range']['label'],
                    'InterruptionMaximum': instance['Range']['max']
                }

    if args.verbose:
        # Don't try to sort these yet!
        sorted_instances = valid_instances
    if args.order_by_price:
        sorted_instances = dict(
            sorted(valid_instances.items(), key=lambda item: item[1]["SpotPrice"]))
    elif args.order_by_interruption:
        sorted_instances = dict(sorted(valid_instances.items(
        ), key=lambda item: item[1]['InterruptionMaximum']))
    else:
        # Sorted by instance type (or rather, family name)
        sorted_instances = dict(sorted(valid_instances.items()))

    if args.verbose or args.json:
        print(json.dumps(sorted_instances, indent=2))
    elif args.csv:
        print("InstanceType,RAM,vCPU,Network,SpotPrice,CappedMaxPods,TheoreticalMaxPods,InterruptionRisk")
        for instance_id in sorted_instances:
            instance = sorted_instances[instance_id]
            print(
                f"{instance['InstanceType']},{instance['RAM']},{instance['vCPU']},{instance['Network']},{instance['SpotPrice']},{instance['CappedMaxPods']},{instance['TheoreticalMaxPods']},{instance['InterruptionRisk']}")
    else:
        headers = ["InstanceType", "RAM", "vCPU", "Network",
                   "SpotPrice", "CappedMaxPods", "TheoreticalMaxPods", "InterruptionRisk"]
        table_data = []
        for instance_id in sorted_instances:
            instance = sorted_instances[instance_id]
            table_data.append((instance['InstanceType'], instance['RAM'], instance['vCPU'], instance['Network'],
                              instance['SpotPrice'], instance['CappedMaxPods'], instance['TheoreticalMaxPods'], instance['InterruptionRisk']))
        print(tabulate(table_data, headers, tablefmt="grid"))


if __name__ == "__main__":
    main()
