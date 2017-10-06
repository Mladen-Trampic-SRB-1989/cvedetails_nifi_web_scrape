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
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.*;
import java.util.stream.Collectors;

@Tags({"html","json","scrape","extract","microsoft","vulnerabilities"})
@CapabilityDescription("Extracts data from Microsoft Vulnerabilities and writes a JSON inside the contents of " +
        "the flowfile.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class MicrosoftVulnerabilitiesExtractor extends AbstractProcessor {

    public static final PropertyDescriptor ATTRIBUTES = new PropertyDescriptor
            .Builder().name("attributes")
            .description("comma separated list of additional flowfile attributes which" +
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

        final String attributesString = context.getProperty(ATTRIBUTES)
                .evaluateAttributeExpressions(flowFile).getValue();
        final Boolean additionalAttributes = attributesString == null;
        final List<String> attributes = (attributesString == null) ?
                new ArrayList<>():
                Arrays.asList(attributesString.split(","));

        final Map<String,String> attributesMap = new HashMap<>();
        if (additionalAttributes) {
            flowFile.getAttributes()
                    .entrySet().stream()
                    .filter(entry -> attributes.contains(entry.getKey()))
                    .forEach(entry ->
                            attributesMap.put(entry.getKey(),entry.getValue()));
        }

        try {
            flowFile = session.write(flowFile, (inputStream, outputStream) -> {
                Document document = Jsoup.parse(inputStream, "UTF-8",
                        "https://technet.microsoft.com");
                JSONObject jsonObj = new JSONObject();

                Elements sections = document.select(".sectionblock");
                String content = sections.stream().map(Element::text).collect(Collectors.joining("\n"));

                jsonObj.put("content",content);
                attributesMap.forEach(jsonObj::put);

                outputStream.write(jsonObj.toString().getBytes("UTF-8"));
            });
            session.transfer(flowFile, SUCCESS);
        } catch (RuntimeException t) {
            getLogger().error("Unable to process HTML: " + t.getMessage());
            session.transfer(flowFile,FAILURE);
        }
    }
}
