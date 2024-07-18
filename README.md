# enterprise-alerts-report

## Example

```
  - name: Generate Report
    uses: CanarysPlayground/enterprise-ghasalerts-count@main
    with:
      enterprise_name: canarys
      github_token: ${{secrets.TOKEN}}

  - name: upload report as artifact
    uses: actions/upload-artifact@v4.3.4
    with:
      name: GHAS Report
      path: github_alerts-with-owners.csv
```
