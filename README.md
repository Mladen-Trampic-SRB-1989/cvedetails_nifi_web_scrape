This is custom NiFi processor, that extracts information from http://www.cvedetails.com/cve/{CVE_ID} pages, where {CVE_ID} represents specific CVE. 
eg.
http://www.cvedetails.com/cve/CVE-2017-1000117/

Extraction is done through library JSOUP, and output is generated with library JSON.

This processor, takes html flowfile that is previously in nifi flow fetched, and extracts data from webpage into specific JSON.
eg.
{\n
	"access_Complexity": {\n
		"Description": "{STRING}",
		"value": "{STRING}"
	},
	"last_Update_Date": "{STRING}",
	"references": "{STRING}",
	"description": "{STRING}",
	"CVSSScore": {DOUBLE},
	"publish_Date": "{STRING}",
	"vulnerability_Type": {
		"value": "{STRING}"
	},
	"gained_Access": "{STRING}",
	"CVE": "{STRING}",
	"availability_Impact": {
		"Description": "{STRING}",
		"value": "{STRING}"
	},
	"confidentiality_Impact": {
		"Description": "{STRING}",
		"value": "{STRING}"
	},
	"CWE_ID": {INTEGER},
	"integrity_Impact": {
		"Description": "{STRING}",
		"value": "{STRING}"
	},
	"authentication": {
		"Description": "{STRING}",
		"value": "{STRING}"
	}
}
