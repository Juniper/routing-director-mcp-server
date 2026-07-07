import os

X_FROM = "ask-paragon"

USE_EXTERNAL_API = os.getenv("USE_EXTERNAL_API", "false").lower() == "true"

if USE_EXTERNAL_API:
    BASE_URL = "https://external.api.endpoint/"
else:
    BASE_URL = None  # Use internal URLs below

def get_url(env_var, default):
    return os.getenv(env_var) or (BASE_URL if BASE_URL else default)

PAPI_URL = get_url("PAPI_URL", "http://papi-internal.papi:8000/")
API_AGG_URL = get_url("API_AGG_URL", "http://api-aggregator.epic:12000/")
INSIGHTS_CONFIG_SERVER = get_url("INSIGHTS_CONFIG_SERVER", "http://config-server.healthbot:9000/")
INSIGHTS_API_SERVER = get_url("INSIGHTS_API_SERVER", "http://api-server.healthbot:9000/")
# x-hb-token for the Insights "custom" topic/user namespace
INSIGHTS_CUSTOM_HB_TOKEN = "$9$o/Ji.5QntpBz3" #nosec
INSIGHTS_VM_AUTH = get_url("INSIGHTS_VM_AUTH", "http://vmauth-victoria-metrics-auth.healthbot:8427/")
FH_ORDER_MGMT = get_url("FH_ORDER_MGMT", "http://order-management.foghorn:11000/")
OCTALK_RPC = get_url("OCTALK_RPC", "http://octalk-rpc.northstar:80/rpc/v1/execute")
PAA_URL = get_url("PAA_URL", "http://paa-orchestrator-service.paa:8092")
ALERTMANAGER_URL = get_url("ALERTMANAGER_URL", "http://alert-manager-service.common:8092")
use_paa_vmdb = os.getenv("USE_PAA_VMDB", "false").lower() == "true"
PF_WEBSERVER_URL = get_url("PF_WEBSERVER_URL", "http://pf-ns-web-restserver.northstar:3301/")
metrics_service_url_key = "METRICS_SERVICE_VMDB_URL" if use_paa_vmdb else "METRICS_SERVICE_TSDB_URL"
default_metrics_service_url = "http://paa-metrics-service.paa:8089" if use_paa_vmdb else "http://paa-metrics-service.paa:8099"
METRICS_SERVICE_URL = os.getenv(metrics_service_url_key, default_metrics_service_url)
TRUST_URL = get_url("TRUST_URL", "http://network.trust:5922/")

# Reading the victoria-metrics credentials set via the k8s secret
VM_USER = os.getenv("VM_USER")
VM_PWD = os.getenv("VM_PWD")
EOP_HOST = os.getenv("EOP_HOST")

BLACKLIST_REQUEST_JUNOS_OPERATIONS = [
    "reboot", "shutdown", "power-off", "delete", "halt", "zeroize", "reload", "terminate", "upgrade", "update"
]
BLACKLIST_REQUEST_JUNOS_COMMANDS_REGEX = "request .* (" + "|".join(BLACKLIST_REQUEST_JUNOS_OPERATIONS) + ")"


ALERT_SEVERITIES = ["SEVERITY_CRITICAL", "SEVERITY_MAJOR", "SEVERITY_MINOR", "SEVERITY_WARNING", "SEVERITY_INFO"]

# Junos XML/RPC tags that must never be run through operational command tools.
# Extend this list as needed to block additional configuration-changing RPCs.
BLOCKED_JUNOS_RPC_TAGS = [
    "load-configuration",
    "delete-config",
    "edit-config",
]


class _RoutingDirectorClientProxy:
    """Stateless proxy that forwards attribute access (e.g. ``con.request``,
    ``con.org_id``) to the per-request Routing Director client stored in the
    request context.

    This lets tool modules keep importing a module-level ``con`` while the
    actual client is created fresh per query (per org) and looked up at call
    time via ``get_con()``.
    """

    def __getattr__(self, name):
        # Imported lazily to avoid import cycles at module load time.
        from utils.lm_calls.connection.client_connection import get_con
        client = get_con()
        if client is None:
            raise RuntimeError(
                "Routing Director client is not initialized for this request. "
                "Ensure create_agent()/set_con() ran before invoking tools."
            )
        return getattr(client, name)


con = _RoutingDirectorClientProxy()
