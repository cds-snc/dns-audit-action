# DNS Audit Action

The purpose of this action is to audit DNS traffic from a GitHub Action workflow. The action achieves this by launching TCPDump and capturing DNS traffic. Traffic is captured in SLL2 packet format and then parsed for UDP packets. Once the packers have been captured the action can be called again with the `output-file` parameter to output the data to a file on JSON format with additional metadata around the GitHub action. From there ur can be processed by sending it to a log analytics workspace or other SIEM, or uploaded as an artifact.

If the action is not called twice, the data will be output to the console as part of the post action step. Should you want to avoid that you can set the `SUPRESS_DNS_AUDIT_OUTPUT` environment variable to `true` in your workflow.


## Inputs

| Name | Description | Required | Default |
| --- | --- | --- | --- |
| file-path | The path to the file to write the PCAP data to | true | /tmp/dns.pcap |
| output-file | The path to the file to write the JSON data to | false | |
| start-tcpdump | Whether or not to start tcpdump | true | true |


## Example of capturing DNS traffic

ex:

```
- name: Capture DNS traffic
  uses:cds-snc/dns-audit-action@main
```

Then just review the `Post Capture DNS Traffic` step in the logs to see the DNS traffic.


## Example of forwarding output data to another location

ex:

```
- name: Capture DNS traffic
  uses:cds-snc/dns-audit-action@main

# Do other things here

- name: Write DNS traffic to file
  uses: cds-snc/dns-audit-action@main
  with:
    output-file: dns_traffic.json

- name: Report deployment to Sentinel
  uses: cds-snc/sentinel-forward-data-action@main
  with:
    file_name: dns_traffic.json
    log_type: GitHubMetadata_CI_DNS_Queries
    log_analytics_workspace_id: ${{ secrets.LOG_ANALYTICS_WORKSPACE_ID }}
    log_analytics_workspace_key: ${{ secrets.LOG_ANALYTICS_WORKSPACE_KEY }}
```

## License
MIT License (MIT)