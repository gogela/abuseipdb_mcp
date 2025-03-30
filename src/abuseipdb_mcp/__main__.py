import logging
import requests
import json
from mcp.server.fastmcp import FastMCP
from typing import Dict, Any, List
from dotenv import load_dotenv
import re
import os

# A simple MCP working with abuseipdb.com API (limited to read-only API calls)
# Own API key required
YOUR_OWN_API_KEY=os.environ["ABUSEIPDB_KEY"]

# Configure logging
logging.basicConfig(filename='abuseipdb_mcp.log', level=logging.INFO, format='%(asctime)s - %(message)s')

mcp = FastMCP("AbuseIPDB")


#ip subnet validator
def is_valid_ip_net(network_string):
    """
    Verifies if a string is a valid IP network/subnet using a regular expression.

    Args:
        network_string: The string to validate.

    Returns:
        True if the string is a valid IP network/subnet, False otherwise.
    """
    ip_network_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[12]?[0-9])$"
    return re.match(ip_network_regex, network_string) is not None

#ip addr validator
def is_valid_ip(ip_string):
    """
    Verifies if a string is a valid IP network/subnet using a regular expression.

    Args:
        network_string: The string to validate.

    Returns:
        True if the string is a valid IP network/subnet, False otherwise.
    """
    ip_network_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(ip_network_regex, ip_string) is not None


#TOOLS
@mcp.tool()
async def check_block(network_query: str = "10.10.10.0/24",  maxAgeInDays: int = 5) -> Dict[str, Any]:
  """
    Search the AbuseIPDB database using specified ip address block.

    This function allows users to search the AbuseIPDB database by providing a block of IP adresses for any reported malicious activity of any IP from the block.
    It returns number of reported malicious activities related to IP adresses in the block in a formatted dictionary.
    The search is limited to a specific history period.

    Parameters:
    - network_query (str): Block of ip adresses in the x.x.x.x/x form to search in the AbuseIPDB.
    - maxAgeInDays (int): The maxAgeInDays parameter determines how old the reports considered in the query search can be. Default is 5.

    Returns:
    - Dict[str, Any]: A dictionary containing IP adresses from the block that were reported as related to a malicious activity, count of reported malicious activities per IP address.
  """
  url = 'https://api.abuseipdb.com/api/v2/check-block'

  if not is_valid_ip_net(network_query):
    return {
            "success": False,
            "error": "Invalid IP network/subnet",
            "results": []
        }

  try:
    querystring = {
        'network':network_query,
        'maxAgeInDays':str(maxAgeInDays),
    }
    headers = {
        'Accept': 'application/json',
        'Key': YOUR_OWN_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    results = decodedResponse['data']['reportedAddress']
    return {
        "success": True,
        "results": results
    }

  except Exception as e:
      return {
          "success": False,
          "error": str(e),
          "results": []
      }

@mcp.tool()
async def check(ip_query: str = "10.10.10.10",  maxAgeInDays: int = 10) -> Dict[str, Any]:
  """
    Search the AbuseIPDB database using specified ip

    This function allows users to search the AbuseIPDB database by providing an IP adress for any reported malicious activity.
    It returns detailed information about the IP (isp, owner, geolocation) and a list of reports of malicious activities (if any).
    The search is limited to a specific history period.

    Parameters:
    - ip_query (str): ip adress in the x.x.x.x form to search in the AbuseIPDB.
    - maxAgeInDays (int): The maxAgeInDays parameter determines how old the reports considered in the query search can be. Default is 10.

    Returns:
    - Dict[str, Any]: A dictionary containing details about the IP adresses including list of reported malicious activities (under dict key <reports>).
  """

  url = 'https://api.abuseipdb.com/api/v2/check'

  if not is_valid_ip(ip_query):
    return {
            "success": False,
            "error": "Invalid IP address",
            "results": []
        }

  try:
    querystring = {
        'ipAddress':ip_query,
        'maxAgeInDays':str(maxAgeInDays),
    }
    headers = {
        'Accept': 'application/json',
        'Key': YOUR_OWN_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    results = json.loads(response.text)

    return {
        "success": True,
        "results": results,
    }

  except Exception as e:
      return {
          "success": False,
          "error": str(e),
          "results": []
      }

@mcp.tool()
async def blacklist(confidenceMinimum: int = 90) -> Dict[str, Any]:
  """
    Query AbuseIPDB database to get blacklist including known malicious IP adresses.

    This function allows users to query the AbuseIPDB database by providing conficenceMinimum score parameter that indicates the confidence level for IP adresses to be included in the blacklist.
    The search returns list of object containing malicious IP, its score and date of the lastes report of its malicious activity.

    Parameters:
    - confidenceMinimum (int): The parameter determines conficence score of IP entries to be included in the list (higher score = more confidence of malicious activity). Default is 90.

    Returns:
    - Dict[str, Any]: A dictionary containing list of malicious IPs, score and the date of lart reported malicious activity.
  """
  try:
    url = 'https://api.abuseipdb.com/api/v2/blacklist'

    querystring = {
        'confidenceMinimum':str(confidenceMinimum)
    }

    headers = {
        'Accept': 'application/json',
        'Key': YOUR_OWN_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    results = decodedResponse['data']

    return {
        "success": True,
        "results": results
    }
  except Exception as e:
    return {
        "success": False,
        "error": str(e),
        "results": []
    }

def main():
    mcp.run()

if __name__ == "__main__":
    main()
