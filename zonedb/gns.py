import subprocess


class GNSRecord:
    """GNS record.

    Attributes:
        nick: The nick of the record.
        ttl: The TTL of the record.
        rdata: The RDATA of the record.
        type: The type of the record.
        zone: The zone of the record.
    """

    def __init__(self, nick, ttl, rdata, type, zone):
        self.nick = nick.rstrip(".")
        self.ttl = ttl
        self.rdata = rdata
        self.type = type
        self.zone = zone.rstrip(".")

    def __str__(self):
        return "%s %i IN %s %s" % (
            self.nick, self.ttl, self.type, self.rdata
        )


proto_to_num = {"translation": 49153, "scheme": 49152}
service_to_num = {"trust": 49152}


def refresh_environment_gns(environment):
    """Refreshes the given environment."""
    print("Refreshing GNS")
    records = {}
    for zone in environment.zones:
        records[zone] = generate_gns_zone_records(zone)
    return records


def generate_gns_zone_records(zone):
    print("Generating GNS records")
    records = []
    for record in zone.records:
        try:
            gns_record = GNSRecord(record.name.split(".")[0], record.ttl, record.rdata, record.rtype, record.name)
            records.append(gns_record)
        except Exception as e:
            continue
    for claim in zone.scheme_claims:
        try:
            record_data = "%i %i %s _scheme._trust.%s" % (
                service_to_num["trust"], proto_to_num["scheme"],
                "12", claim.scheme,
            )
            gns_record = GNSRecord(claim.name.split(".")[0], zone.soa_ttl, record_data, "BOX", claim.name)
            records.append(gns_record)
        except Exception as e:
            continue
    for trust_list in zone.trust_lists:
        try:
            record_line = "%i %i %s %i %i \"%s\"" % (
                service_to_num["trust"], proto_to_num[trust_list.list_type],
                "256", 10, 1, trust_list.url,
            )
            gns_record = GNSRecord(trust_list.name.split(".")[0], zone.soa_ttl, record_line, "BOX", trust_list.name)
            records.append(gns_record)
        except Exception as e:
            continue
        for cert in trust_list.certs:
            try:
                record_line = "%i %i %s %i %i %i %s" % (
                    service_to_num["trust"], proto_to_num[trust_list.list_type],
                    "53", cert.usage, cert.selector, cert.matching,
                    cert.data
                )
                gns_record = GNSRecord(trust_list.name.split(".")[0], zone.soa_ttl, record_line, "BOX", trust_list.name)
                records.append(gns_record)
            except Exception as e:
                continue
    return records


def reload_gns(records):
    for zone, record in records.items():
        reload_gns_zone(record, zone)


# TODO use proper TTL
def reload_gns_zone(records, apex):
    print("Reloading GNS zone")
    zones = set()
    for record in records:
        zones.add(record.zone)

    zone_keys = {}

    for path in zones:
        for zone in path.split("."):
            try:
                zone_keys[zone] = subprocess.check_output(['gnunet-identity', '--display', '-e', zone, '-q'])
                if zone_keys[zone] is None or len(zone_keys[zone]) < 5:
                    raise Exception("No key")
                # subprocess.call('gnunet-namestore -X -z ' + zone, shell=True) # TODO fix duplicate entries
            except:
                subprocess.call('gnunet-identity --create="' + zone + '"', shell=True)
                zone_keys[zone] = subprocess.check_output(['gnunet-identity', '--display', '-e', zone, '-q'])

    for apex in zones:
        path = apex.split(".")[::-1]
        previous_zone = path[0]
        for zone in path[1:]:
            pkey = zone_keys[zone]
            try:
                entry = subprocess.check_output(
                    ["gnunet-namestore", "-z", previous_zone, "-Z", pkey.decode().rstrip("\n")])
                if entry.decode().split(".")[0] == zone:
                    previous_zone = zone
                    continue
                else:
                    subprocess.call('gnunet-namestore -a -p -n ' + zone + ' --type PKEY -V ' + pkey.decode().strip("\n")
                                    + ' -e never ' + '-z ' + previous_zone, shell=True)
                    previous_zone = zone
            except subprocess.CalledProcessError as e:
                subprocess.call('gnunet-namestore -a -p -n ' + zone + ' --type PKEY -V ' + pkey.decode().strip("\n")
                                + ' -e never ' + '-z ' + previous_zone, shell=True)
                previous_zone = zone

    for record in records:
        try:
            subprocess.call('gnunet-namestore -a -p -n "@" --type ' + record.type + ' -V \'' + record.rdata
                            + '\' -e never ' + '-z ' + record.nick, shell=True)
        except Exception as e:
            continue
