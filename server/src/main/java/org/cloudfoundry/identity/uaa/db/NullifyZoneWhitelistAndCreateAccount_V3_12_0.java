/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.Links.Logout;
import org.cloudfoundry.identity.uaa.zone.Links.SelfService;
import org.cloudfoundry.identity.uaa.zone.ZoneAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NullifyZoneWhitelistAndCreateAccount_V3_12_0 implements SpringJdbcMigration {

    static final String ID_ZONE_FIELDS = "id,config";
    static final String IDENTITY_ZONES_QUERY = "select " + ID_ZONE_FIELDS + " from identity_zone ";

    Log logger = LogFactory.getLog(NullifyZoneWhitelistAndCreateAccount_V3_12_0.class);

    @Override
    public synchronized void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        List<IdentityZone> identityZones = retrieveIdentityZones(jdbcTemplate);
        for (IdentityZone zone : identityZones) {
            try{
                zone.getConfig().getLinks().getLogout().setWhitelist(Arrays.asList("http*://*"));
                zone.getConfig().getLinks().getSelfService().setSignup("");
                updateIdentityZone(zone, jdbcTemplate);
            } catch (NullPointerException e) {
                logger.warn("There was a null config component for " + zone.getId() + ". Moving on to next zone.");
                zone.getConfig().getLinks().setLogout(new Logout()).getLogout().setWhitelist(Arrays.asList("http*://*"));
                if(zone.getConfig().getLinks().getSelfService() == null) {
                    zone.getConfig().getLinks().setSelfService(new SelfService());
                }
            }
        }

    }

    private void updateIdentityZone(IdentityZone identityZone, JdbcTemplate jdbcTemplate) {
        String ID_ZONE_UPDATE_FIELDS = "config=?";
        String UPDATE_IDENTITY_ZONE_SQL = "update identity_zone set " + ID_ZONE_UPDATE_FIELDS + " where id=?";

        try {
            jdbcTemplate.update(UPDATE_IDENTITY_ZONE_SQL, new PreparedStatementSetter() {
                @Override
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1,identityZone.getConfig() != null ?
                            JsonUtils.writeValueAsString(identityZone.getConfig()) :null);
                    ps.setString(2, identityZone.getId().trim());
                }
            });
        } catch (DuplicateKeyException e) {
            //duplicate subdomain
            throw new ZoneAlreadyExistsException(e.getMostSpecificCause().getMessage(), e);
        }
    }

    private List<IdentityZone> retrieveIdentityZones(JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.query(IDENTITY_ZONES_QUERY, mapper);
    }

    private RowMapper<IdentityZone> mapper = (rs, rowNum) -> {
        IdentityZone identityZone = new IdentityZone();

        identityZone.setId(rs.getString(1).trim());
        String config = rs.getString(2);
        if (StringUtils.hasText(config)) {
            try {
                identityZone.setConfig(JsonUtils.readValue(config, IdentityZoneConfiguration.class));
            } catch (JsonUtils.JsonUtilException e) {
                logger.error("Invalid zone configuration found for zone id:"+identityZone.getId(), e);
                identityZone.setConfig(new IdentityZoneConfiguration());
            }
        }
        return identityZone;
    };

}
