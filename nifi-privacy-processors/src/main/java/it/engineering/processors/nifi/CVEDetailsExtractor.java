/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.engineering.processors.nifi;

import it.engineering.processors.nifi.cvedetailsutility.CVEFeatures;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.util.StringUtils;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;

@Tags({"html", "json", "scrape", "extract"})
@CapabilityDescription("Extracts data from a different number of HTML sources and writes a JSON inside the contents of " +
        "the flowfile.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute = "", description = "")})
@WritesAttributes({@WritesAttribute(attribute = "", description = "")})
public class CVEDetailsExtractor extends AbstractProcessor {



    public static final Relationship SUCCESS = new Relationship.Builder()
            .name("success")
            .description("The resulting JSON flowfile is sent to this relationship.")
            .build();

    public static final Relationship FAILURE = new Relationship.Builder()
            .name("failure")
            .description("If there is any error in processing, the flowfile is sent to this relationship.")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(SUCCESS);
        relationships.add(FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }



        try {
            flowFile = session.write(flowFile, (inputStream, outputStream) -> {

                Document document = Jsoup.parse(inputStream, "UTF-8", "http://www.cvedetails.com");
                Element htmlPage = document.select("#contentdiv").first();
                Elements tables = htmlPage.select("tbody");

                String cveDetails = tables.select("h1").text();
                String cveDetailsTimeInfo = tables.select(".cvedetailssummary").select(".datenote").text();
                tables.select(".cvedetailssummary").select(".datenote").remove();
                String cveDetailsDescription = tables.select(".cvedetailssummary").text();
                CVEFeatures cveFeaturesObject = new CVEFeatures();
                cveFeaturesObject.setCVE(cveDetails.split(":")[1].replaceAll("\\s+", ""));
                Elements tableCVEScoreAndVulnerabilityTypes = tables.select("#cvssscorestable").select("tr");
                Elements tableCVEScoreAndVulnerabilityTypesKeys = tableCVEScoreAndVulnerabilityTypes.select("th");
                Elements tableCVEScoreAndVulnerabilityTypesValues = tableCVEScoreAndVulnerabilityTypes.select("td");
                cveFeaturesObject.setPublishDate(cveDetailsTimeInfo.split(":")[0]);
                String publishedString = cveDetailsTimeInfo.substring(0, cveDetailsTimeInfo.indexOf("Last")).split(":")[1].replaceAll("\\s+", "");
                String lastUpdatedString = cveDetailsTimeInfo.substring(cveDetailsTimeInfo.indexOf("Last")).split(":")[1].replaceAll("\\s+", "");
                cveFeaturesObject.setPublishDate(publishedString);
                cveFeaturesObject.setLastUpdateDate(lastUpdatedString);
                cveFeaturesObject.setDescription(cveDetailsDescription);
                if (!tables.select("#vulnrefstable").select("td").isEmpty()) {
                    List<String> references = new ArrayList<String>();
                    for(Element E : tables.select("#vulnrefstable").select("td")){
                        references.add(E.text());
                    }
                    cveFeaturesObject.setReferences(StringUtils.join(references,","));
                }
                for (int i = 0; i < tableCVEScoreAndVulnerabilityTypesKeys.size(); i++) {
                    Element row = tableCVEScoreAndVulnerabilityTypesValues.get(i);
                    String description = "";
                    if (!row.select(".cvssdesc").isEmpty()) {
                        description = row.select(".cvssdesc").text();
                        description = description.replaceAll("\\(", "");
                        description = description.replaceAll("\\)", "");

                    }
                    row.select(".cvssdesc").remove();
                    String key = tableCVEScoreAndVulnerabilityTypesKeys.get(i).text();
                    String value = tableCVEScoreAndVulnerabilityTypesValues.get(i).text();
                    if (description.isEmpty()) {
                        cveFeaturesObject.forInputStringChoseSetMethod(key, value);
                    } else {
                        cveFeaturesObject.forInputStringChoseSetMethod(key, value, description);
                    }


                }

                JSONObject jsonObj = new JSONObject(cveFeaturesObject);
                outputStream.write(jsonObj.toString().getBytes("UTF-8"));


            });
            session.transfer(flowFile, SUCCESS);
        } catch (RuntimeException t) {
            getLogger().error("Unable to process ExtractTextProcessor file " + t.getLocalizedMessage());
            getLogger().error("{} failed to process due to {}; rolling back session", new Object[]{this, t});
            session.transfer(flowFile, FAILURE);
        }

    }
}
