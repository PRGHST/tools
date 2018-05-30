# Author:
# PureReactions
# @PureReactions
#
# Version:
# 1.0.2
#
# Description:
# Parses Office 365 HTML Links from Carbon Black
#
# External Dependencies:    
# cbapi, argparser, configparser, yara
#
# Reference(s):
# https://cbapi.readthedocs.io/en/latest/installation.html
# http://yara.readthedocs.io/en/v3.7.0/gettingstarted.html
# https://pypi.org/project/yara-python/

from cbapi.response import CbResponseAPI, Process
from collections import OrderedDict
from datetime import datetime, timedelta
import argparse, configparser, json, os, re, time, urllib, yara


class CommonUtils:   
    url_regex = re.compile("([a-z]{3,}\:\/\/[\S]{4,})", re.IGNORECASE)
    safelink_regex = re.compile("[a-z]{3,}\:\/\/([\S]{1,}\.)*safelinks\.protection\.outlook\.com\/\?url=", re.IGNORECASE)
    safelinks_param = re.compile(".*url=", re.IGNORECASE)

    @property
    def domain_whitelist_patterns(self):
        return [ re.compile(str(i), re.IGNORECASE)
            for i in json.loads(self.configs.get("filters", "domains"))
            ]

    @property
    def configs(self):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        config = configparser.ConfigParser()
        config.read(config_file)
        return config       

    def whitelistDomain(self, link):
        for pattern in self.domain_whitelist_patterns:
            if re.match(pattern, self.parseDomain(link)):
                return False
        return True

    def analyzeLinks(self, links):
        analyzer = Analyzer()
        analysis_results = [ {
            "url" : link,
            "yara" : analyzer.linkScan(link),
            }
            for link in links
            ]
        return analysis_results

    def parseLink(self, cmdline):
        url = re.findall(self.url_regex, cmdline)
        if url:
            matches = [ match.group() for match in re.finditer(self.safelink_regex, url[0]) if match ]
            if matches:
                parsed_link = urllib.unquote(self.safelinks_param.sub("", url[0]).partition("&data=")[0])
                return parsed_link
            else:
                parsed_link = url[0].replace("\"", "").replace("'", "")
                return parsed_link
        parsed_link = "NO URL"
        return parsed_link
        
    def parseDomain(self, link):
        domain = link.split("//", 1)[-1].split("/")[0].split("?")[0]
        return domain  


class Analyzer(CommonUtils):
    #  *** YARA Scanning Component ***
    @property
    def link_rules(self):
        link_rules = yara.compile(filepath=self.configs.get("settings", "link_rules"))
        return link_rules

    @property
    def domain_rules(self):
        domain_rules = yara.compile(filepath=self.configs.get("settings", "domain_rules"))
        return domain_rules

    def processMatches(self, matches):
        if matches:
            return [ {"rule_name" : hit.rule, "rule_tags" : hit.tags} for hit in matches ]
        else:
            return []

    def domainScan(self, link):
        domain = self.parseDomain(link)
        matches = self.domain_rules.match(data=domain)
        return self.processMatches(matches)

    def linkScan(self, link):
        matches = self.processMatches(self.link_rules.match(data=link))
        domain_matches = self.domainScan(link)
        matches.extend(domain_matches)
        return matches


class Trawler(CommonUtils):
    def __init__(self, args):
        self.args = args
        self.cb_response_session = CbResponseAPI()

    def outputResults(self, results):
        if self.args.format == "json":
            date = str((datetime.utcnow() - timedelta(hours=1)).strftime("%Y_%m_%d_%H_%M")) # Year_Month_Day_Hour_Minute
            file_name = os.path.join(self.args.output_dir, "%s_results.json" % date)
            with open(file_name, "wb") as file:
                file.write(json.dumps(results))

    def formatResults(self, results):
        temp_queue, grouped_results = [], []
        for res in results["cb_results"]:
            name = res["username"]
            if name not in temp_queue:
                temp_queue.append(name)
                urls = list(OrderedDict.fromkeys([ res["url"] for res in results["cb_results"] if name == res["username"] ]))
                hostnames = list(OrderedDict.fromkeys([ res["hostname"] for res in results["cb_results"] if name == res["username"] ]))
                links_analysis = self.analyzeLinks(urls)
            grouped_results.append({ 
                "username" : name, 
                "hostnames" : hostnames, 
                "host_count" : len(hostnames), 
                "url_count" : len(urls),
                "urls" : links_analysis,
            })
        del temp_queue
        return grouped_results

    def search(self):
        cb_proc_search = self.cb_response_session.select(Process)
        cb_proc_search.where(self.args.query)
        query_results = list(self.cb_response_session.select(Process).where(self.args.query).group_by("id"))
        results = { "cb_results" : [ 
            {"hostname" : str(result.hostname), 
            "username" : str(result.username), 
            "proc_start" : str(result.start),
            "url" : str(self.parseLink(result.cmdline).encode("utf8")) 
            } for result in query_results
            if self.whitelistDomain(str(self.parseLink(result.cmdline).encode("utf8")))
            ] 
            }
        formatted_results = self.formatResults(results)
        self.outputResults(formatted_results)


def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    arg_parser = argparse.ArgumentParser(description="This Python script retrieves Office 365 Safelinks or URI/URLs in the command line from Carbon Black Response", usage="")
    arg_parser.add_argument("--query", type=str, default="(parent_name:acrord32.exe OR parent_name:outlook.exe) cmdline:*safelinks.protection.outlook* OR cmdline:*http* start:-1h", help="Query for Carbon Black")
    arg_parser.add_argument("--interval", default=3600, type=int, help="Time interval for the repeating query (seconds)")   
    arg_parser.add_argument("--format", default='json', type=str, help="Format type of the results as (json)")
    arg_parser.add_argument("--output-dir", default=current_dir, type=str, help="Output directory of results")
    parsed_args = arg_parser.parse_args()
    new_session = Trawler(parsed_args)
    while True:
        new_session.search()
        time.sleep(parsed_args.interval)


if __name__ == "__main__":
    main()
