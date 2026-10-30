"""
LDAP / Active Directory authentication service.

Supports:
  - Simple bind (username + password against AD)
  - LDAP search to find user attributes (email, display name, groups)
  - Group-to-role mapping (AD groups → IT Admin / Engineer / Viewer / End User)
  - Auto-provisioning: creates a local User record on first successful LDAP login
  - Sync: updates name/email/role on subsequent logins
  - Connection pooling via ldap3's built-in connection strategy

LDAP config is stored encrypted in Organization.ldap_config as JSON:
{
  "server":           "ldap://dc01.company.com" or "ldaps://dc01.company.com:636",
  "base_dn":          "DC=company,DC=com",
  "bind_dn":          "CN=netaudit,OU=Service Accounts,DC=company,DC=com",
  "bind_password":    "encrypted",          # AES-256 encrypted
  "user_search_base": "OU=Users,DC=company,DC=com",
  "user_filter":      "(sAMAccountName={username})",   # or (uid={username})
  "email_attr":       "mail",
  "name_attr":        "displayName",
  "groups_attr":      "memberOf",
  "role_mappings": {
    "CN=IT-Admins,OU=Groups,DC=company,DC=com":    "it_admin",
    "CN=IT-Engineers,OU=Groups,DC=company,DC=com": "it_engineer",
    "CN=IT-Viewers,OU=Groups,DC=company,DC=com":   "it_viewer"
    // Any user not in a mapped group defaults to "end_user"
  },
  "use_tls": true,
  "tls_verify": true
}
"""
from dataclasses import dataclass
from typing import Optional
import structlog
from ldap3 import (
    Server, Connection, ALL, NTLM, SIMPLE,
    AUTO_BIND_TLS_BEFORE_BIND, SUBTREE, ALL_ATTRIBUTES,
    Tls,
)
from ldap3.core.exceptions import (
    LDAPBindError, LDAPSocketOpenError,
    LDAPSocketReceiveError, LDAPInvalidCredentialsResult
)
import ssl
from ldap3.utils.conv import escape_filter_chars

from app.models.models import UserRole

log = structlog.get_logger()


@dataclass
class LDAPUserInfo:
    """Normalised user attributes from LDAP."""
    username: str
    email: str
    display_name: str
    role: UserRole
    groups: list[str]
    dn: str


class LDAPService:
    """
    Stateless LDAP helper — creates a new connection per operation.
    Safe to instantiate once and call from async code (ldap3 is sync,
    we call it in a thread pool in the auth route).
    """

    def __init__(self, config: dict):
        self.server_url = config.get("server", "")
        self.base_dn = config.get("base_dn", "")
        self.bind_dn = config.get("bind_dn", "")
        self.bind_password = config.get("bind_password", "")
        self.user_search_base = config.get("user_search_base") or self.base_dn
        self.user_filter_template = config.get("user_filter", "(sAMAccountName={username})")
        self.email_attr = config.get("email_attr", "mail")
        self.name_attr = config.get("name_attr", "displayName")
        self.groups_attr = config.get("groups_attr", "memberOf")
        self.role_mappings: dict[str, str] = config.get("role_mappings", {})
        self.use_tls = config.get("use_tls", True)
        self.tls_verify = config.get("tls_verify", True)

    def _make_server(self) -> Server:
        tls = None
        if self.use_tls or self.server_url.startswith("ldaps://"):
            tls = Tls(
                validate=ssl.CERT_REQUIRED if self.tls_verify else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT if self.tls_verify else ssl.PROTOCOL_TLS,
            )
        return Server(self.server_url, get_info=ALL, tls=tls)

    def _service_connection(self) -> Connection:
        """Open a connection bound with the service account."""
        server = self._make_server()
        conn = Connection(
            server,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=AUTO_BIND_TLS_BEFORE_BIND if self.use_tls else True,
            authentication=SIMPLE,
            raise_exceptions=True,
        )
        return conn

    def test_connection(self) -> tuple[bool, str]:
        """
        Test service account bind. Returns (success, message).
        Safe to call from a thread pool.
        """
        try:
            conn = self._service_connection()
            conn.unbind()
            return True, "Connection successful"
        except LDAPBindError as e:
            log.warning("ldap_test_bind_failed", error=type(e).__name__)
            return False, "Bind failed — check the bind DN and password"
        except LDAPSocketOpenError as e:
            log.warning("ldap_test_unreachable", error=type(e).__name__)
            return False, "Cannot reach the LDAP server — check the address, port and TLS settings"
        except Exception as e:
            log.error("ldap_test_failed", error=type(e).__name__)
            return False, "Unexpected error while testing the LDAP connection"

    def authenticate(self, username: str, password: str) -> Optional[LDAPUserInfo]:
        """
        Authenticate a user with their username and password.

        Steps:
          1. Bind with service account to search for the user's DN
          2. Attempt a bind as that user with their password
          3. Re-bind as service account to read attributes and group membership
          4. Map groups to roles, return LDAPUserInfo

        Returns None if credentials are wrong.
        Raises LDAPSocketOpenError if server is unreachable.
        """
        try:
            # Step 1 — find user DN via service account search
            svc_conn = self._service_connection()
            search_filter = self.user_filter_template.format(username=escape_filter_chars(username))

            svc_conn.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.email_attr,
                    self.name_attr,
                    self.groups_attr,
                    "sAMAccountName",
                    "userPrincipalName",
                    "cn",
                ],
            )

            if not svc_conn.entries:
                log.warning("ldap_user_not_found", username=username)
                return None

            entry = svc_conn.entries[0]
            user_dn = entry.entry_dn
            svc_conn.unbind()

            # Step 2 — bind as the user to verify password
            server = self._make_server()
            try:
                user_conn = Connection(
                    server,
                    user=user_dn,
                    password=password,
                    auto_bind=AUTO_BIND_TLS_BEFORE_BIND if self.use_tls else True,
                    authentication=SIMPLE,
                    raise_exceptions=True,
                )
                user_conn.unbind()
            except (LDAPBindError, LDAPInvalidCredentialsResult):
                log.info("ldap_invalid_credentials", username=username)
                return None

            # Step 3 — re-read full attributes with service account
            svc_conn2 = self._service_connection()
            svc_conn2.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.email_attr,
                    self.name_attr,
                    self.groups_attr,
                    "sAMAccountName",
                    "userPrincipalName",
                ],
            )
            entry = svc_conn2.entries[0] if svc_conn2.entries else None
            svc_conn2.unbind()

            if not entry:
                return None

            # Extract attributes safely
            email = self._attr(entry, self.email_attr) or \
                    self._attr(entry, "userPrincipalName") or \
                    f"{username}@ldap"
            display_name = self._attr(entry, self.name_attr) or username

            # Step 4 — map groups to role
            raw_groups = entry[self.groups_attr].values if hasattr(entry, self.groups_attr) else []
            groups = [str(g) for g in raw_groups]
            role = self._map_role(groups)

            log.info("ldap_auth_success", username=username, role=role, groups_count=len(groups))
            return LDAPUserInfo(
                username=username,
                email=email,
                display_name=display_name,
                role=role,
                groups=groups,
                dn=user_dn,
            )

        except LDAPSocketOpenError as e:
            log.error("ldap_server_unreachable", server=self.server_url, error=str(e))
            raise
        except Exception as e:
            log.error("ldap_auth_error", username=username, error=str(e))
            return None

    def search_users(self, query: str, limit: int = 20) -> list[dict]:
        """
        Search for users in LDAP by name or username.
        Used for the user import/invite UI.
        """
        query = escape_filter_chars(query)
        try:
            conn = self._service_connection()
            search_filter = (
                f"(|(sAMAccountName=*{query}*)"
                f"(displayName=*{query}*)"
                f"(mail=*{query}*))"
            )
            conn.search(
                search_base=self.user_search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[
                    self.email_attr,
                    self.name_attr,
                    "sAMAccountName",
                    self.groups_attr,
                ],
                size_limit=limit,
            )
            results = []
            for entry in conn.entries:
                username = self._attr(entry, "sAMAccountName") or ""
                email = self._attr(entry, self.email_attr) or ""
                name = self._attr(entry, self.name_attr) or username
                raw_groups = entry[self.groups_attr].values if hasattr(entry, self.groups_attr) else []
                role = self._map_role([str(g) for g in raw_groups])
                results.append({
                    "username": username,
                    "email": email,
                    "display_name": name,
                    "role": role,
                    "dn": entry.entry_dn,
                })
            conn.unbind()
            return results
        except Exception as e:
            log.error("ldap_search_error", query=query, error=str(e))
            return []

    def _attr(self, entry, attr_name: str) -> Optional[str]:
        """Safely read a single-value LDAP attribute as a string."""
        try:
            val = entry[attr_name].value
            return str(val) if val else None
        except Exception:
            return None

    def _map_role(self, groups: list[str]) -> UserRole:
        """
        Check group DNs against the role_mappings config.
        Most-privileged role wins if user is in multiple mapped groups.
        Defaults to END_USER if no group matches.
        """
        priority = {
            "it_admin": 4,
            "it_engineer": 3,
            "it_viewer": 2,
            "end_user": 1,
        }
        best_role = "end_user"
        best_priority = 1

        for group_dn in groups:
            # Case-insensitive DN comparison
            for mapped_dn, role_str in self.role_mappings.items():
                if group_dn.lower() == mapped_dn.lower():
                    p = priority.get(role_str, 0)
                    if p > best_priority:
                        best_role = role_str
                        best_priority = p

        role_map = {
            "it_admin": UserRole.IT_ADMIN,
            "it_engineer": UserRole.IT_ENGINEER,
            "it_viewer": UserRole.IT_VIEWER,
            "end_user": UserRole.END_USER,
        }
        return role_map.get(best_role, UserRole.END_USER)


def ldap_service_from_org(org) -> Optional[LDAPService]:
    """
    Build an LDAPService from an org's stored config.
    Decrypts the bind password before use.
    Returns None if LDAP is not enabled or not configured.
    """
    if not org.ldap_enabled or not org.ldap_config:
        return None

    from app.core.security import decrypt
    config = dict(org.ldap_config)

    # Decrypt the stored bind password
    if config.get("bind_password"):
        config["bind_password"] = decrypt(config["bind_password"])

    return LDAPService(config)
