# AgentThreatMapper

Outil en ligne de commande qui analyse la sécurité d'un agent IA déployé sur Azure en comparant :

- ce que l'agent est **censé faire** (son intention métier, déclarée dans un fichier texte) ;
- ce que son identité cloud **peut réellement faire** (ses permissions Azure réelles).

## Inputs

1. `agent_context.json` — export structuré produit via Azure CLI (`az`) : identité managée, role assignments, ressources du resource group, Key Vault, Storage, Azure AI Search, diagnostic settings / logs.
2. Un fichier texte décrivant le rôle métier de l'agent : ce qu'il est autorisé à faire, ce qui lui est interdit, son niveau d'autonomie.

## Pipeline

1. **Export CLI** (`azure_export/`) — interroge Azure via `az` et produit `agent_context.json`.
2. **Normalisation** (`normalization/`, `models/`) — transforme le JSON brut et le fichier de rôle métier en objets Python (dataclasses).
3. **Modèle de menace** (`threat_model/`) — reconstruit les flux de données (utilisateur → agent → LLM → RAG → tools → ressources Azure → logs), identifie les trust boundaries et les points d'entrée non fiables.
4. **Moteur de règles** (`rules/`) — règles déterministes inspirées de l'OWASP LLM Top 10 et des patterns Azure IAM, qui détectent les findings (excessive agency, capability mismatch, Key Vault sans restriction réseau, rôle trop large, Storage pouvant empoisonner un RAG, absence de logs, prompt injection impact path...).
5. **Rapport** (`reporting/`) — formate les findings (titre, sévérité, explication, mitigation) en rapport Markdown lisible.

## Structure du projet

```
src/agent_threat_mapper/
├── cli.py            # Point d'entrée CLI (commande `atm`)
├── azure_export/     # Étape 1 : export Azure via `az`
├── models/           # Modèles de données partagés (ressources Azure, intention métier, threat model)
├── normalization/    # Étape 2 : parsing JSON brut + fichier de rôle métier
├── threat_model/     # Étape 3 : construction du modèle de menace
├── rules/            # Étape 4 : moteur de règles + règles par catégorie
└── reporting/        # Étape 5 : formatage du rapport

tests/                 # Tests, miroir de la structure src/, avec fixtures hors-ligne
```

## Statut

Projet en cours de démarrage — la structure est en place, l'implémentation des différentes étapes du pipeline reste à faire.
