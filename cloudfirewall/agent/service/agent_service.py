import logging
import os
import time
import uuid

import grpc


from cloudfirewall.common.taskmanager import TaskManager
from cloudfirewall.grpc import agent_pb2_grpc
from cloudfirewall.grpc.agent_pb2 import HeartbeatRequest

from cloudfirewall.grpc import nft_pb2_grpc
from cloudfirewall.grpc.nft_pb2 import RulesetRequest

from cloudfirewall.version import VERSION

HEARTBEAT_INTERVAL = 5  # Seconds

RULESET_INTERVAL = 2


class AgentService(TaskManager):

    def __init__(self, agent, channel):
        self.logger = logging.getLogger(AgentService.__name__)
        super(AgentService, self).__init__()

        self.agent = agent
        self.channel = channel

        # Setup the stub for GRPC service
        self.stub = agent_pb2_grpc.AgentStub(self.channel)

        # Schedule all periodic tasks
        self.register_task("send_heartbeat", self.send_heartbeat, interval=HEARTBEAT_INTERVAL)

    def send_heartbeat(self):
        uname = os.uname()
        heartbeat_request = HeartbeatRequest(version=VERSION,
                                             request_id=str(uuid.uuid4()),
                                             node_id=self.agent.agent_uuid,
                                             node_name=uname.nodename,
                                             timestamp=int(time.time()))

        try:
            response = self.stub.Heartbeat(heartbeat_request)
            self.logger.info(f"Heartbeat response: [request_id: %s]", response.request_id)
        except grpc.RpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.CANCELLED:
                self.logger.error("GRPC service cancelled")
            elif rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                self.logger.error("GRPC service unavailable")
            else:
                self.logger.error(f"Unknown RPC error: code={rpc_error.code()}, message={rpc_error.details()}")



class AgentFirewall(TaskManager):

    def __init__(self, agent, channel):
        self.logger = logging.getLogger(AgentFirewall.__name__)
        super(AgentFirewall, self).__init__()

        self.agent = agent
        self.channel = channel

        # Setup the stub for GRPC service
        self.stub = nft_pb2_grpc.FirewallRulesStub(self.channel)

        # Schedule all periodic tasks

        self.register_task("send_rulesets", self.send_rulesets, interval=RULESET_INTERVAL)


    def send_rulesets(self):

        ruleset_request = RulesetRequest(request_id = str(uuid.uuid4()))


        try:

            response = self.stub.Agent(ruleset_request)
            self.logger.info(response.request_id)
            self.logger.info(
                {"table":response.table,"chain":response.chain_in,"protocol":response.protocol,
                 "port":response.port,"ip_saddr":response.ip_saddr,"ip_daddr":response.ip_daddr,
                  "rule":response.rule
                 })

            sudoPassword = 'gagan@gbs123'

            command_flush = f'nft flush ruleset'

            f = os.system('echo %s|sudo -S %s' % (sudoPassword, command_flush))
            print(f)


            command = f'nft add table inet {response.table}'

            p = os.system('echo %s|sudo -S %s' % (sudoPassword , command))
            print(p)

            # chain_inbound = 'nft add chain inet {} {}'
            # a_in = chain_inbound.format(response.table, response.chain_in) + "" + "\{ type filter hook input priority 0\; policy accept\; \}"
            # c_in = os.system('echo %s|sudo -S %s' % (sudoPassword, a_in))
            # print(c_in)
            # #To add new rules
            # rule_in = [
            #     f'nft add rule inet {response.table} {response.chain_in} ip saddr {response.ip_saddr} drop',
            #
            # ]
            # for i in rule_in:
            #     r_in = os.system('echo %s|sudo -S %s' % (sudoPassword, i))
            #     print(r_in)
            #
            # chain_outbound = 'nft add chain inet {} {}'
            # a_out= chain_outbound.format(response.table,response.chain_out) + "" + "\{ type filter hook output priority 0\; policy accept\; \}"
            # c_out = os.system('echo %s|sudo -S %s' % (sudoPassword, a_out))
            # print(c_out)
            # # To add new rules
            # rule_out = [
            #
            #     f'nft add rule inet {response.table} {response.chain_out} ip daddr { response.ip_daddr } drop'
            # ]
            # for i in rule_out:
            #     r_out = os.system('echo %s|sudo -S %s' % (sudoPassword, i))
            #     print(r_out)





        except grpc.RpcError as rpc_error:
            if rpc_error.code() == grpc.StatusCode.CANCELLED:
                self.logger.error("GRPC service cancelled")
            elif rpc_error.code() == grpc.StatusCode.UNAVAILABLE:
                self.logger.error("GRPC service unavailable")
            else:
                self.logger.error(f"Unknown RPC error: code={rpc_error.code()}, message={rpc_error.details()}")
