import sys
import json
import urllib.request
import urllib.parse


class standardArgs:
    readStdin = False
    fileName = None
    output = "report.html"
    stdinValue = ""


def printHelp():
    print("Usage:")
    print("clair-html [options] [inputFile]")
    print("")
    print("Options:")
    print("--       Read from stdin (piped) - will ignore inputFile")
    print("-o       Output file destination (default ./report.html)")
    print("")
    print("inputFile (or stdin) must be clair report in json format")


def parseArguments():
    print("Parsing arguments " + ",".join(sys.argv))
    index = 1
    success = True
    parsed = standardArgs()
    if len(sys.argv) <= index:
        print("No arguments provided! See help for usage.")
        printHelp()
        return False, parsed
    while index < len(sys.argv):
        arg = sys.argv[index]
        if arg.startswith("-"):
            if arg == "--":
                parsed.readStdin = True
            elif arg == "-o":
                parsed.output = sys.argv[index + 1]
                index += 1
            else:
                print("Unknown argument [" + arg + "]; see help for usage.")
                printHelp()
                success = False
        elif parsed.fileName is None:
            parsed.fileName = arg
        else:
            print("Unknown or additional input [" + arg + "]; see help for usage.")
            printHelp()
            success = False
        index += 1
    if parsed.readStdin:
        parsed.stdinValue = sys.stdin
    if not (parsed.readStdin or parsed.fileName):
        success = False
    return success, parsed


def parseJson(args):
    print("Parsing Json from " + ("stdin" if args.readStdin else args.fileName))
    try:
        if args.readStdin:
            return True, json.loads(args.stdinValue)
        else:
            file = open(args.fileName, "r")
            return True, json.load(file)
    except ValueError:
        print("Error parsing json.")
    except IOError:
        print("Error reading file [" + args.fileName + "].")
    return False, {}


def generateHTMLReport(args, json):
    print("Generating report file " + args.output)
    outFile = None
    try:
        outFile = open(args.output, "w")
    except IOError:
        print("Unable to open file [" + args.output + "] for writing.")
        return
    outFile.write("<html>")
    outFile.write(
        "<style>body { text-align: center; } table { text-align: center; }</style>"
    )
    outFile.write("<h1>Vulnerability Report</h1>")
    outFile.write(
        "<p>"
        + json["manifest_hash"]
        + "<br>"
        + json["distributions"]["1"]["pretty_name"]
        + "</p>"
    )
    outFile.write("<table border='1'>")
    outFile.write("<tr>")
    outFile.write("<th>Package Name</th>")
    outFile.write("<th>Package Version</th>")
    outFile.write("<th>Fix Version</th>")
    outFile.write("<th>Severity v3</th>")
    outFile.write("<th>Severity v2</th>")
    outFile.write("<th>Vuln Record</th>")
    outFile.write("<th>Vuln Description</th>")
    outFile.write("</tr>")
    for package in json["package_vulnerabilities"].keys():
        for vuln in json["package_vulnerabilities"][package]:
            vulExtraData = getVulnData(json["vulnerabilities"][vuln]["name"])
            outFile.write("<tr>")
            outFile.write("<td>" + json["packages"][package]["name"] + "</td>")
            outFile.write("<td>" + json["packages"][package]["version"] + "</td>")
            outFile.write(
                "<td>" + json["vulnerabilities"][vuln]["fixed_in_version"] + "</td>"
            )
            severityLevels = getSeverity(vulExtraData)
            outFile.write("<td>" + severityLevels[0] + "</td>")
            outFile.write("<td>" + severityLevels[1] + "</td>")
            outFile.write(
                '<td><a href="'
                + json["vulnerabilities"][vuln]["links"]
                + '">'
                + json["vulnerabilities"][vuln]["name"]
                + "</a></td>"
            )
            outFile.write(
                "<td>" + json["vulnerabilities"][vuln]["description"] + "</td>"
            )
            outFile.write("</tr>")
    outFile.write("</table>")
    outFile.write("</html>")
    outFile.close()


def getVulnData(vulnID):
    ret = None
    vulnIDOnly = vulnID.split(" ")[0]
    try:
        url = urllib.request.urlopen(
            "https://services.nvd.nist.gov/rest/json/cve/1.0/" + vulnIDOnly
        )
        try:
            ret = json.loads(url.read().decode("utf-8"))
        except ValueError:
            print("Error parsing CVE data from nist.")
    except urllib.error.HTTPError:
        print("CVE not found [" + vulnIDOnly + "]")
    return ret


def getSeverity(vulnData):
    ret = []
    if vulnData is None:
        return ["UNKNOWN", "UNKNOWN"]
    try:
        ret.append(
            vulnData["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"][
                "baseSeverity"
            ]
        )
    except KeyError:
        ret.append("UNKNOWN")
    try:
        ret.append(
            vulnData["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
        )
    except KeyError:
        ret.append("UNKNOWN")
    return ret


def main():
    argsParsed, args = parseArguments()
    if argsParsed:
        jsonParsed, parsedJson = parseJson(args)
        if jsonParsed:
            generateHTMLReport(args, parsedJson)


if __name__ == "__main__":
    main()
