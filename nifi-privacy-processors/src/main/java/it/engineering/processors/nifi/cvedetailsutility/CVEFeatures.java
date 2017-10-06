package it.engineering.processors.nifi.cvedetailsutility;

import java.util.HashMap;
import java.util.Map;

public class CVEFeatures {
    private static Map<String, Object> createMap(String key, Object o) {
        Map<String, Object> myMap = new HashMap<String, Object>();
        myMap.put(key, o);
        return myMap;
    }

    private static Map<String, Object> createMapWithDescription(String key, Object o) {
        Map<String, Object> myMap = new HashMap<String, Object>();
        myMap.put(key, o);
        myMap.put("Description","");
        return myMap;
    }

    public static Map<String, Object> getAccess_Complexity() {
        return Access_Complexity;
    }

    public void setAccessComplexity(String accessComplexity) {
        this.Access_Complexity.replace("value", accessComplexity);
    }
    public void setAccessComplexityDescription(String accessComplexityDescription) {
        this.Access_Complexity.replace("Description", accessComplexityDescription);
    }

    private static  Map<String, Object> Access_Complexity = createMapWithDescription("value", "");




    private static Map<String, Object> Authentication = createMapWithDescription("value", "");

    public static Map<String, Object> getAuthentication() {
        return Authentication;
    }

    public void setAuthentication(String authentication) {
        this.Authentication.replace("value", authentication);
    }

    public void setAuthenticationDescription(String authenticationDescription) {
        this.Authentication.replace("Description", authenticationDescription);
    }

    private static Map<String, Object> Availability_Impact = createMapWithDescription("value", "");

    public static Map<String, Object> getAvailability_Impact() {
        return Availability_Impact;
    }

    public void setAvailabilityImpact(String availabilityImpact) {
        this.Availability_Impact.replace("value", availabilityImpact);
    }

    public void setAvailabilityImpactDescription(String availabilityImpactDescription) {
        this.Availability_Impact.replace("Description", availabilityImpactDescription);
    }


    private static String CVE = "";

    public static String getCVE() {
        return CVE;
    }

    public void setCVE(String CVE){
        this.CVE = CVE;
    }




    private static Double CVSSScore = Double.valueOf(0);

    public static Double getCVSSScore() {
        return CVSSScore;
    }

    public void setCVSSScore(Double cvssscore) {
        this.CVSSScore = cvssscore;
    }



    private static Integer CWE_ID = 0;


    public static Integer getCWE_ID() {
        return CWE_ID;
    }

    public static void setCWE_ID(Integer cweId) {
        CWE_ID = cweId;
    }

    private static Map<String, Object> Confidentiality_Impact = createMapWithDescription("value", "");

    public static Map<String, Object> getConfidentiality_Impact() {
        return Confidentiality_Impact;
    }

    public void setConfidentialityImpact(String confidentialityImpact) {
        this.Confidentiality_Impact.replace("value", confidentialityImpact);
    }

    public void setConfidentialityImpactDescription(String confidentialityImpactDescription) {
        this.Confidentiality_Impact.replace("Description", confidentialityImpactDescription);
    }

    public static String getGained_Access() {
        return Gained_Access;
    }

    public static void setGainedAccess(String gained_Access) {
        Gained_Access = gained_Access;
    }

    private static String Gained_Access = "";



    private static Map<String, Object> Integrity_Impact = createMapWithDescription("value", "");

    public static Map<String, Object> getIntegrity_Impact() {
        return Integrity_Impact;
    }

    public void setIntegrityImpact(String integrityImpact) {
        this.Integrity_Impact.replace("value", integrityImpact);
    }
    public void setIntegrityImpactDescription(String integrityImpactDescription) {
        this.Integrity_Impact.replace("Description", integrityImpactDescription);
    }

    private static String Last_Update_Date = "";

    public static String getLast_Update_Date() {
        return Last_Update_Date;
    }

    public static void setLastUpdateDate(String last_Update_Date) {
        Last_Update_Date = last_Update_Date;
    }



    private static String Publish_Date ="";

    public static String getPublish_Date() {
        return Publish_Date;
    }

    public static void setPublishDate(String publish_Date) {
        Publish_Date = publish_Date;
    }

    private static String description = "";

    public static String getDescription() {
        return description;
    }

    public static void setDescription(String description) {
        CVEFeatures.description = description;
    }

    public static String getReferences() {
        return references;
    }

    public static void setReferences(String references) {
        CVEFeatures.references = references;
    }

    private static String references = "";


    private static Map<String, Object> Vulnerability_Type = createMap("value", "");

    public static Map<String, Object> getVulnerability_Type() {
        return Vulnerability_Type;
    }

    public void setVulnerabilityType(String vulnerabilityType) {
        this.Vulnerability_Type.replace("value", vulnerabilityType);
    }

    public void forInputStringChoseSetMethod(String parametrized, String value, String description){
        if(StringSimilarity.similarity(parametrized,"Access_Complexity") > 0.8) {
            setAccessComplexity(value);
            setAccessComplexityDescription(description);
        }else if (StringSimilarity.similarity(parametrized,"Authentication") > 0.8){
            setAuthentication(value);
            setAuthenticationDescription(description);
        }else if (StringSimilarity.similarity(parametrized,"Availability_Impact") > 0.8){
            setAvailabilityImpact(value);
            setAvailabilityImpactDescription(description);
        }else if (StringSimilarity.similarity(parametrized,"Integrity_Impact") > 0.8){
            setIntegrityImpact(value);
            setIntegrityImpactDescription(description);
        }else if (StringSimilarity.similarity(parametrized,"Confidentiality_Impact") > 0.8){
            setConfidentialityImpact(value);
            setConfidentialityImpactDescription(description);
        }
    }
    public void forInputStringChoseSetMethod(String parametrized, String value){
        if(StringSimilarity.similarity(parametrized,"CVSS_Score") > 0.8){
            setCVSSScore(Double.valueOf(value));
        }else if (StringSimilarity.similarity(parametrized,"CWE_ID") > 0.8){
            setCWE_ID(Integer.valueOf(value));
        }else if (StringSimilarity.similarity(parametrized,"Gained_Access") > 0.8){
            setGainedAccess(value);
        }else if (StringSimilarity.similarity(parametrized,"Vulnerability_Type") > 0.8){
            setVulnerabilityType(value);
        }else if(StringSimilarity.similarity(parametrized,"Access_Complexity") > 0.8) {
            setAccessComplexity(value);
        }else if (StringSimilarity.similarity(parametrized,"Authentication") > 0.8){
            setAuthentication(value);
        }else if (StringSimilarity.similarity(parametrized,"Availability_Impact") > 0.8){
            setAvailabilityImpact(value);
        }else if (StringSimilarity.similarity(parametrized,"Integrity_Impact") > 0.8){
            setIntegrityImpact(value);
        }else if (StringSimilarity.similarity(parametrized,"Confidentiality_Impact") > 0.8){
            setConfidentialityImpact(value);
        }
    }


}
