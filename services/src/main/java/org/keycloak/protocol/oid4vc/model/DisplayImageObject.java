/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

/**
 * Represents an image object, containing details for an image.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonAutoDetect(
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        setterVisibility = JsonAutoDetect.Visibility.NONE
)
public class DisplayImageObject {

    @JsonProperty("uri")
    private String uri;

    @JsonProperty("url")
    private String url;

    @JsonProperty("alt_text")
    private String altText;

    public String getUri() {
        return uri;
    }

    public DisplayImageObject setUri(String uri) {
        this.uri = uri;
        return this;
    }

    public String getUrl() {
        return url;
    }

    public DisplayImageObject setUrl(String url) {
        this.url = url;
        return this;
    }

    public String getAltText() {
        return altText;
    }

    public DisplayImageObject setAltText(String altText) {
        this.altText = altText;
        return this;
    }

    public String toJsonString() {
        try {
            return JsonSerialization.writeValueAsString(this);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static DisplayImageObject fromJsonString(String jsonString) {
        try {
            return JsonSerialization.readValue(jsonString, DisplayImageObject.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DisplayImageObject that)) return false;

        if (getUri() != null ? !getUri().equals(that.getUri()) : that.getUri() != null) return false;
        if (getUrl() != null ? !getUrl().equals(that.getUrl()) : that.getUrl() != null) return false;
        return getAltText() != null ? getAltText().equals(that.getAltText()) : that.getAltText() == null;
    }

    @Override
    public int hashCode() {
        int result = getUri() != null ? getUri().hashCode() : 0;
        result = 31 * result + (getUrl() != null ? getUrl().hashCode() : 0);
        result = 31 * result + (getAltText() != null ? getAltText().hashCode() : 0);
        return result;
    }
}
