"""Produces the zone master data."""
import logging
from time import time
import subprocess
import ldns
from zonedb.models import Environment

proto_to_num = {"translation": 1003, "scheme": 1002}
service_to_num = {"trust": 242}

records = {}


def refresh_master(session):
    """Recreates all master data for the zone data in the database."""
    for env in session.query(Environment):
        refresh_environment(session, env)
        reload_master(env)


def reload_master(environment):
    for name, record_lines in records.items():
        subprocess.call('gnunet-identity --create="' + name + '"', shell=True)
        subprocess.call('gnunet-namestore -X -z' + name + ' -t ANY', shell=True)

        cmd = 'gnunet-namestore --zone=' + name + ' --add -p -e never'  # TODO change never

        for line in record_lines:
            try:
                subprocess.call(cmd + ' ' + line, shell=True)
                print(line)
            except Exception as e:
                print(e)
                continue


def refresh_environment(session, environment):
    """Refreshes the given environment."""
    for zone in environment.zones:
        refresh_zonefile(session, environment, zone)


def refresh_zonefile(session, environment, zone):
    record_lines = []
    for record in zone.records:
        try:
            record_line = "-V '%s' -t %s -n %s" % (
                record.rdata, record.rtype, "'@'"
            )
        except Exception as e:
            print(e)
            continue
        record_lines.append(record_line)
    for claim in zone.scheme_claims:
        try:
            record_line = "-V '%i %i %s _scheme._trust.%s' -t BOX -n %s" % (
                service_to_num["trust"], proto_to_num["scheme"],
                "12", claim.scheme,
                claim.name.split(".")[0]
            )
        except Exception as e:
            print(e)
            continue
        record_lines.append(record_line)
    for trust_list in zone.trust_lists:
        try:
            record_line = "-V '%i %i %s %i %i \"%s\"' -t BOX -n %s" % (
                service_to_num["trust"], proto_to_num[trust_list.list_type],
                "256", 10, 1, trust_list.url,
                trust_list.name.split(".")[0]
            )
        except Exception as e:
            print(e)
            continue
        record_lines.append(record_line)
        for cert in trust_list.certs:
            try:
                record_line = "-V '%i %i %s %i %i %i %s' -t BOX -n %s" % (
                    service_to_num["trust"], proto_to_num[trust_list.list_type],
                    "53", cert.usage, cert.selector, cert.matching,
                    cert.data, trust_list.name.split(".")[0]
                )
            except Exception as e:
                print(e)
                continue
            record_lines.append(record_line)

    records[zone.apex.split(".")[0]] = record_lines


def get_ds(session, environment, zone):
    res = ""
    return res
