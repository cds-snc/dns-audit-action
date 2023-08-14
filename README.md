# Generic Project Template

This repository provides some base files for setting up a repository at
CDS. Plan is to create more project template for specific technologies:

- project-template-terraform
- project-template-python
- project-template-nodejs

Note that default community health files are maintained at https://github.com/cds-snc/.github 

## Using output data 

ex:

```
- name: Write DNS traffic to file
  uses: ./
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