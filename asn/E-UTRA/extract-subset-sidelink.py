in_req_block = False
with open("EUTRA-Sidelink-Preconf-Subset-Markup.asn", "r") as infile, open("EUTRA-Sidelink-Preconf-Subset.asn",
                                                                   "w") as outfile:
    outfile.write("-- Subset of EUTRA-Sidelink-Preconf required by Ieee1609Dot3Wee\n")
    for line in infile:
        if line.strip().startswith("-- Required"):
            in_req_block = True
            outfile.write("\n")
            continue
        if line.strip().startswith("-- EndRequired"):
            in_req_block = False
            outfile.write("\n")
            # outfile.write(line)
        if in_req_block:
            outfile.write(line)
