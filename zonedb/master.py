"""Produces the zone master data."""

from time import time
import subprocess
import ldns
from zonedb.models import Environment


def refresh_master(session):
    """Recreates all master data for the zone data in the database."""
    for env in session.query(Environment):
        refresh_environment(session, env)
        # reload_master(env)


# def reload_master(environment):
#    subprocess.call(environment.nsd_reload, shell=True)

def create_zone(session, name):
    subprocess.call('gnunet-identity --create="' + name + '"', )


def refresh_environment(session, environment):
    """Refreshes the given environment."""
    for zone in environment.zones:
        create_zone(session, zone.apex)
        refresh_zone(session, environment, zone)


def refresh_zone(session, environment, zone):
    cmd = 'gnunet-namestore'

    record_lines = []
    for record in zone.records:
        try:
            rr = record.rr()
            record_line = zone.soa_ttl + " " + record.rtype + " P " + rr
        except:
            continue
        record_lines.append(record_line)
    for claim in zone.scheme_claims:
        try:
            rr = claim.rr()
            record_line = zone.soa_ttl + " " + claim.rtype + " P " + rr
        except:
            continue
        record_lines.append(record_line)
    for trust_list in zone.trust_lists:
        try:
            rr = trust_list.rr()
            record_line = zone.soa_ttl + " " + trust_list.rtype + " P " + rr
        except:
            continue
        record_lines.append(record_line)
        for cert in trust_list.certs:
            try:
                rr = cert.rr(trust_list)
                record_line = zone.soa_ttl + " " + cert.rtype + " P " + rr
            except:
                continue
            record_lines.append(record_line)

    args = ['--zone=' + zone.apex, '--add', '-n=' + zone.mname]
    for line in record_lines:
        args.append('-R ' + line)
    try:
        subprocess.call(cmd + " ".join(args), shell=True)
    except:
        return


def load_key_list(session, environment, zone):
    """Loads the keys for a zone and returns an ldns_key_list."""
    res = ldns.ldns_key_list()
    hold = []
    for key in zone.keys:
        key = load_key(session, environment, zone, key.key, key.ksk)
        hold.append(key)
        res.push_key(key)
    return (hold, res)


def load_key(session, environment, zone, key, ksk):
    open(environment.key_file, "w").write(key.private_key)
    res = ldns.ldns_key.new_frm_fp(open(environment.key_file, "r"))
    res.set_flags(257 if ksk else 256)
    res.set_origttl(zone.dnskey_ttl)
    res.set_pubkey_owner(ldns.ldns_dname(str(zone.apex)))
    res.set_use(True)
    return res


def get_ds(session, environment, zone):
    res = ""
    (hold, key_list) = load_key_list(session, environment, zone)
    for key in list(key_list.keys()):
        if key.flags() == 257:
            rr = key.key_to_rr()
            ds = ldns.ldns_key_rr2ds(rr, ldns.LDNS_SHA256)
            if res:
                res += '\n'
            res += str(ds)
    return res
