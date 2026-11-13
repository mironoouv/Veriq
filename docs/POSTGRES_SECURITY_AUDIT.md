# PostgreSQL 17.11 audit checks

The dedicated Linux workflow provisions temporary databases with the
repository migration entry point. It checks the catalog against effective
function grants and compares the clean and upgraded schemas' ACLs. The
upgrade path seeds synthetic tenant data and issues a session at 0015,
then runs the catalog integration suite at head. Runtime denial probes
connect as the provisioned API and worker logins.

Run the PostgreSQL security audit workflow on the branch to reproduce.
Foundation CI covers the existing HTTPS, session, tenant and worker suites
separately. The additional role probes cover representative forbidden
operations. A passing run does not certify each function body or exclude
authorization defects in every call path.
