"""Resolve configured routes without probing or selecting an alternative path."""
from __future__ import annotations

from dataclasses import dataclass
from enclave_gateway.config import TargetNodeSpec


@dataclass(frozen=True)
class TargetRoute:
    execution_hop: str
    jumps: tuple[TargetNodeSpec, ...]

    @property
    def transport(self):return 'ssh' if self.execution_hop=='appliance' else 'rdp_vfs'


def resolve_target_route(config, target):
    chain=[];seen={target.name};node=target
    while True:
        via=node.via.lstrip('@')
        if via=='appliance':return TargetRoute('appliance',tuple(reversed(chain)))
        if via in ('bastion',''):
            if not config.bastion.enabled:
                raise ValueError('Target route requires the disabled RDP Bastion: '+target.name+'. Set its approved SSH route explicitly with via: appliance or a configured SSH jump; no fallback was attempted.')
            return TargetRoute('bastion',tuple(reversed(chain)))
        if via in seen:raise ValueError('Circular TargetNode via routing: '+target.name)
        if via not in config.targets:raise ValueError('Unknown hop in TargetNode routing: '+via)
        seen.add(via);node=config.targets[via];chain.append(node)


def route_summary(config):
    result={}
    for name,target in config.targets.items():
        route=resolve_target_route(config,target)
        result[name]={'transport':route.transport,'execution_hop':route.execution_hop,
                      'ssh_jumps':[node.name for node in route.jumps],
                      'worker_required':route.execution_hop=='bastion','automatic_fallback':False}
    return result
