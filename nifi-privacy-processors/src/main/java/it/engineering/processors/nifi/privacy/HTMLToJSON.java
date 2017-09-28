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
package it.engineering.processors.nifi.privacy;


import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.Validator;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.json.JSONArray;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;

@Tags({"html","json","scrape","extract"})
@CapabilityDescription("Extracts data from a different number of HTML sources and writes a JSON inside the contents of " +
        "the flowfile.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class HTMLToJSON extends AbstractProcessor {

    public static final PropertyDescriptor SOURCE = new PropertyDescriptor
            .Builder().name("source")
            .description("the name of the source for the HTML data.")
            .required(true)
            .expressionLanguageSupported(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor ATTRIBUTES = new PropertyDescriptor
            .Builder().name("attributes")
            .description("comma separated list of additional flowfile attributes the values of which" +
                    "will be added to the resulting JSON.")
            .required(false)
            .expressionLanguageSupported(true)
            .addValidator(Validator.VALID)
            .build();

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
        descriptors.add(SOURCE);
        descriptors.add(ATTRIBUTES);
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
        if ( flowFile == null ) {
            return;
        }

        final String source = context.getProperty(SOURCE).evaluateAttributeExpressions(flowFile).getValue();
        final String attributesString = context.getProperty(ATTRIBUTES)
                .evaluateAttributeExpressions(flowFile).getValue();
        final String[] attributes = (attributesString == null) ?
                new String[1]:
                attributesString.split(",");

        final Map<String,String> attributesMap = new HashMap<>();
        for (String key: attributes) {
            if (flowFile.getAttributes().containsKey(key)) {
                attributesMap.put(key,flowFile.getAttribute(key));
            }
        }

        try {
            flowFile = session.write(flowFile, (inputStream, outputStream) -> {
                switch (source){
                    case "http://www.cvedetails.com":
                        Document document = Jsoup.parse(inputStream, "UTF-8","http://www.cvedetails.com");
                        Element table = document.select("#cvssscorestable").first();
                        Elements KEYS = table.select("th");
                        Elements VALUES = table.select("tr");
                        JSONObject jsonObj = new JSONObject();
                        JSONArray jsonArr = new JSONArray();
                        JSONObject jo = new JSONObject();
                        for (int i = 0, l = KEYS.size(); i < l; i++) {
                            String key = KEYS.get(i).text();
                            key = key.replaceAll("\\s+","_");
                            key = key.replace("(","");
                            key = key.replace(")","");
                            key = key.toLowerCase();
                            String value = VALUES.get(i).text();
                            jo.put(key, value);
                        }
                        jsonArr.put(jo);
                        jsonObj.put("CVSSCORE", jsonArr);
                        for (Map.Entry<String,String> me : attributesMap.entrySet()) {
                            jsonObj.put(me.getKey(),me.getValue());
                        }

                        outputStream.write(jsonObj.toString().getBytes("UTF-8"));
                }
            });
            session.transfer(flowFile, SUCCESS);
        } catch (RuntimeException t) {
            getLogger().error("Unable to process ExtractTextProcessor file " + t.getLocalizedMessage());
            getLogger().error("{} failed to process due to {}; rolling back session", new Object[] { this, t });
            session.transfer(flowFile,FAILURE);
        }

        // TODO implement


    }
}
