import logging

from queue import Queue

from cloudfirewall.grpc import agent_pb2_grpc, agent_pb2
from cloudfirewall.grpc import nft_pb2_grpc, nft_pb2


class FirewallAgentServicer(agent_pb2_grpc.AgentServicer):

    def __init__(self, server):
        self.logger = logging.getLogger(FirewallAgentServicer.__name__)

        self.server = server
        self.command_queue = Queue()

        # Add the servicers to the server
        agent_pb2_grpc.add_AgentServicer_to_server(self, server)

    def Heartbeat(self, request, context):
        self.logger.info("Heartbeat request: [request: %s, peer: %s]", request.request_id, context.peer())
        response = agent_pb2.ServerResponseAck(
            request_id=request.request_id,
        )
        return response

    def get_commands(self):
        return self.commands


class AgentFirewallServicer(nft_pb2_grpc.FirewallRulesServicer):

    def __init__(self, server):

        self.logger = logging.getLogger(AgentFirewallServicer.__name__)

        self.server = server
        self.command_queue = Queue()

        # Add the servicers to the server
        nft_pb2_grpc.add_FirewallRulesServicer_to_server(self, server)

    def Agent(self, request, context,):

        nftables = {
            "nftables":[
                {"flush":{"ruleset":None }},
                {"add": {"table":{
                    "family":"inet",
                    "name": "MasterFirewall"
                }}},
                {"add":{"rule":{
                    "family":"inet",
                    "table":"MasterFirewall",
                    "chain":"INBOUND",
                    "protocol":["tcp","udp","icmp"],
                    "ip_saddr":["192.168.0.0-192.168.255.255","172.16.0.0-172.31.255.255","10.0.0.0-10.255.255.255"],
                    "ip_daddr":["192.168.0.0-192.168.255.255","172.16.0.0-172.31.255.255","10.0.0.0-10.255.255.255"],
                    "tcp_sport":"0-65535",
                    "tcp_dport": "0-65535",
                    "udp_sport": "0-65535",
                    "udp_dport": "0-65535",
                }}},
                {"add": {"rule": {
                    "family": "inet",
                    "table": "MasterFirewall",
                    "chain": "OUTBOUND",
                    "protocol": ["tcp", "udp", "icmp"],
                    "ip_saddr": ["192.168.0.0-192.168.255.255", "172.16.0.0-172.31.255.255", "10.0.0.0-10.255.255.255"],
                    "ip_daddr": ["192.168.0.0-192.168.255.255", "172.16.0.0-172.31.255.255", "10.0.0.0-10.255.255.255"],
                    "tcp_sport": "0-65535",
                    "tcp_dport": "0-65535",
                    "udp_sport": "0-65535",
                    "udp_dport": "0-65535",
                }}}
            ]
        }
        # print(nftables ,"\n")

        self.logger.info("Agent request: [request: %s, peer: %s]", request.request_id, context.peer())
        self.logger.info("Agent Firewall request: [request: %s, peer: %s]",request.request_rules,context.peer())

        response = nft_pb2.Rulesets(

           request_id=request.request_id,
           request_rules = request.request_rules,
           table = "Master",
           chain_in = "INPUT",
           chain_out = "OUTPUT",
           protocol = "tcp",
           port = 20,
           ip_saddr = "192.168.0.0",
           ip_daddr = "13.250.4.102",
           rule = 1,

        )
        return response
