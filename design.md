I want to create a report showing which Certificate Authorities are submitting precertificates to each Certificate Transparency log, with a focus on static ("tiled") logs first. Please write a Python script that obtains a selection of certificates from each of the static logs and then determines which Certificate Authority issued each one. Then create a report showing a breakdown (with percentage) of Certificate Authority certs in each CT log.

Use the list of CT logs at https://www.gstatic.com/ct/log_list/v3/log_list.json, which uses the schema at https://www.gstatic.com/ct/log_list/v3/log_list_schema.json. Download and save these files for re-use.

After the static log breakdown report is generated, I'll add support for RFC 6962 CT logs, so please write the code in an extensible manner, and have it save the data used to build the report, so it can be augmented later.
