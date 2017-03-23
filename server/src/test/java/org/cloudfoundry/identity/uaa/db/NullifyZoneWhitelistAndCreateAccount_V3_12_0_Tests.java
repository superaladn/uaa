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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class NullifyZoneWhitelistAndCreateAccount_V3_12_0_Tests extends JdbcTestBase {

    private IdentityZoneProvisioning provisioning;
    private NullifyZoneWhitelistAndCreateAccount_V3_12_0 migration;
    private RandomValueStringGenerator generator;

    @Before
    public void setUpNullifyWhitelist() {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        migration = new NullifyZoneWhitelistAndCreateAccount_V3_12_0();
        generator = new RandomValueStringGenerator();
    }

    @Test
    public void ensure_that_whitelist_and_create_account_gets_nullified() throws Exception {
        IdentityZoneConfiguration zoneExistingCreateAccount = new IdentityZoneConfiguration();
        zoneExistingCreateAccount.getLinks().getSelfService().setSignup("/create_account");
        
        IdentityZoneConfiguration zoneNullSelfService = new IdentityZoneConfiguration();
        zoneNullSelfService.getLinks().setSelfService(null);
        
        IdentityZoneConfiguration zoneExistingWhitelist = new IdentityZoneConfiguration();
        zoneExistingWhitelist.getLinks().getLogout().setWhitelist(Arrays.asList("http://something"));
        
        IdentityZoneConfiguration zoneEmptyWhitelist = new IdentityZoneConfiguration();
        zoneEmptyWhitelist.getLinks().getLogout().setWhitelist(Collections.emptyList());
        
        IdentityZoneConfiguration zoneNullWhitelist = new IdentityZoneConfiguration();
        zoneNullWhitelist.getLinks().getLogout().setWhitelist(null);
        
        IdentityZoneConfiguration zoneNullLink = new IdentityZoneConfiguration();
        zoneNullLink.setLinks(null);

        IdentityZoneConfiguration zoneNullLogout = new IdentityZoneConfiguration();
        zoneNullLogout.getLinks().setLogout(null);
        
        List<IdentityZoneConfiguration> zoneConfigs = Arrays.asList(zoneExistingCreateAccount, 
                zoneNullSelfService, zoneExistingWhitelist, zoneEmptyWhitelist,
                zoneNullWhitelist, zoneNullLink, zoneNullLogout);
        List<IdentityZone> zones = new ArrayList<IdentityZone>();
        for (IdentityZoneConfiguration zoneConfig : zoneConfigs) {
            String zoneId = generator.generate();
            IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
            zones.add(zone);
            zone.setConfig(zoneConfig);
            IdentityZone created = provisioning.create(zone);
        }

        migration.migrate(jdbcTemplate);
        for (IdentityZone zone : zones) {
            IdentityZone result = provisioning.retrieve(zone.getId());
            assertEquals(result.getConfig().getLinks().getLogout().getWhitelist(), Arrays.asList("http*://**"));
            assertEquals(result.getConfig().getLinks().getSelfService().getSignup(), "");

        }
    }

}