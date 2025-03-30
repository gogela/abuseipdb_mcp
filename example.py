#!pip install smolagents[mcp]
#!pip install smolagents
#!pip install mcp

#smolagents example for abuseipd_mcp

import os
from smolagents import ToolCollection, CodeAgent, HfApiModel
from mcp import StdioServerParameters
from smolagents import DuckDuckGoSearchTool

YOUR_HF_TOKEN="hftoken..."
YOUR_IPDB_TOKEN="abuseipdbtoken..."

os.environ["HF_TOKEN"]=YOUR_HF_TOKEN
server_parameters = StdioServerParameters(
    command="uvx",
    args=["abuseipdb_mcp"],
    env={"ABUSEIPDB_KEY": YOUR_IPDB_TOKEN, **os.environ},
)

with ToolCollection.from_mcp(server_parameters) as tool_collection:
    agent = CodeAgent(
        model=HfApiModel(),
        # additional_authorized_imports=['json'],
        tools=[*tool_collection.tools, DuckDuckGoSearchTool()],
        add_base_tools=True)
    print(len(tool_collection.tools))
    print(tool_collection.tools[0].description)
    agent.run(f"Find 2 malicious IP adresses and provide details about them including ISP and type of their malicious activity")
