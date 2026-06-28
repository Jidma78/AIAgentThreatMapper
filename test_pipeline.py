from pathlib import Path
from agent_threat_mapper.normalization.context_parser import parse_context
from agent_threat_mapper.normalization.intent_parser import parse_intent
from agent_threat_mapper.threat_model.builder import build_threat_model

from agent_threat_mapper.rules.engine import run_rules
from agent_threat_mapper.normalization.intent_parser import parse_intent
from pathlib import Path


print("=== STAGE 2 : parsing des deux inputs ===\n")
ctx = parse_context(Path("agent_context.json"))
intent = parse_intent(Path("agent_role.txt"))

print(f"Agent déclaré : {intent.name}")
print(f"Autonomie : {intent.autonomy_level.value}")
print(f"Actions autorisées : {len(intent.allowed_actions)}")
print(f"Actions interdites : {len(intent.forbidden_actions)}")

print("\n=== STAGE 3 : construction du threat model ===\n")
tm = build_threat_model(ctx, intent)

print(f"Nœuds ({len(tm.nodes)}) :")
for n in tm.nodes:
    entry = " [ENTRÉE NON FIABLE]" if n.untrusted_entry else ""
    print(f"  {n.id} — {n.kind.name} — zone {n.trust_zone.name}{entry}")

print(f"\nTrust boundaries ({len(tm.boundaries)}) :")
for b in tm.boundaries:
    print(f"  {b.id} : {b.name}")

print("\n=== Chemins depuis un point d'entrée non fiable vers chaque ressource ===\n")
for rnode in tm.resource_nodes():
    roles = ", ".join(r.role_definition_name for r in rnode.applicable_roles) or "aucun"
    print(f"Ressource : {rnode.label}  (rôles applicables : {roles})")
    paths = tm.paths_from_untrusted_to(rnode.id)
    if not paths:
        print("  Aucun chemin depuis un point d'entrée non fiable")
    for p in paths:
        chain = " → ".join(n.id for n in p.nodes)
        vector = p.lateral_vector_label()
        suffix = f"  [vecteur latéral : {vector}]" if vector else "  [accès direct]"
        print(f"  {chain}{suffix}")
        boundaries = ", ".join(b.id for b in p.crossed_boundaries)
        print(f"     boundaries franchies : {boundaries}")
    log = "oui" if tm.reaches_log_sink(rnode.id) else "NON"
    print(f"  Atteint un log sink : {log}\n")

print("\n=== Vérification arêtes inter-ressources ===\n")
from agent_threat_mapper.models.threat_model import NodeKind
for e in tm.edges:
    src = tm.get_node(e.source_id)
    tgt = tm.get_node(e.target_id)
    if src.kind == NodeKind.AZURE_RESOURCE and tgt.kind == NodeKind.AZURE_RESOURCE:
        print(f"  {e.source_id} → {e.target_id} [{e.label}]")


print("\n=== STAGE 4 : moteur de règles ===\n")
findings = run_rules(tm, intent)
print(f"{len(findings)} finding(s) détecté(s)\n")
for f in sorted(findings, key=lambda x: x.severity.value):
    print(f"[{f.severity.value.upper()}] {f.rule_id} — {f.title}")
    print(f"  Ressources : {', '.join(f.affected_resources)}")
    print(f"  {f.explanation[:120]}...")
    print(f"  Mitigation : {f.mitigation[:100]}...")
    if f.owasp_ref:
        print(f"  OWASP : {f.owasp_ref}")
    print()