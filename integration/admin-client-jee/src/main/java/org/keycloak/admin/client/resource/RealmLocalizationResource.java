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

package org.keycloak.admin.client.resource;

import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

public interface RealmLocalizationResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<String> getRealmSpecificLocales();

    /**
     * Get the localization texts for the given locale.
     *
     * @param locale the locale
     * @return the localization texts
     */
    @Path("{locale}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, String> getRealmLocalizationTexts(final @PathParam("locale") String locale);


    /**
     * DEPRECATED - Get the localization texts for the given locale.
     *
     * @param locale the locale
     * @param useRealmDefaultLocaleFallback whether the localization texts for the realm default locale should be used
     *        as fallbacks in the result
     * @return the localization texts
     * @deprecated use {@link #getRealmLocalizationTexts(String)}, in order to retrieve localization texts without
     *             fallbacks. If you need fallbacks, call the endpoint multiple time with all the relevant locales (e.g.
     *             "de" in case of "de-CH") - the realm default locale is NOT the only fallback to be considered.
     */
    @Deprecated
    @Path("{locale}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, String> getRealmLocalizationTexts(final @PathParam("locale") String locale,
            @QueryParam("useRealmDefaultLocaleFallback") Boolean useRealmDefaultLocaleFallback);


    @Path("{locale}/{key}")
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    String getRealmLocalizationText(final @PathParam("locale") String locale, final @PathParam("key") String key);


    @Path("{locale}")
    @DELETE
    void deleteRealmLocalizationTexts(@PathParam("locale") String locale);

    @Path("{locale}/{key}")
    @DELETE
    void deleteRealmLocalizationText(@PathParam("locale") String locale, @PathParam("key") String key);

    @Path("{locale}/{key}")
    @PUT
    @Consumes(MediaType.TEXT_PLAIN)
    void saveRealmLocalizationText(@PathParam("locale") String locale, @PathParam("key") String key, String text);

    @Path("{locale}")
    @POST
    @Consumes("application/json")
    void createOrUpdateRealmLocalizationTexts(@PathParam("locale") String locale, Map<String, String> localizationTexts);
}
