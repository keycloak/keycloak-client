/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.representations.idm;

import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ErrorRepresentation {
    private String field;
    private String errorMessage;
    private Object[] params;
    private List<ErrorRepresentation> errors;

    public ErrorRepresentation() {
    }

    public ErrorRepresentation(String field, String errorMessage, Object[] params) {
        super();
        this.field = field;
        this.errorMessage = errorMessage;
        this.params = params;
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
    
    public Object[] getParams() {
        return this.params;
    }
    
    public void setParams(Object[] params) {
        this.params = params;
    }

    public void setErrors(List<ErrorRepresentation> errors) {
        this.errors = errors;
    }

    public List<ErrorRepresentation> getErrors() {
        return errors;
    }
}
