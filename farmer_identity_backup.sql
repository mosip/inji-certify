--
-- PostgreSQL database dump
--

-- Dumped from database version 17.0
-- Dumped by pg_dump version 17.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: farmer_identity; Type: TABLE DATA; Schema: certify; Owner: postgres
--

INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('4567538768', 'John Doe', '989898999', '1980-05-15', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Farmhouse",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "123 Farm Road",
        "addressLocality": "Farmville",
        "addressRegion": "Rural State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": "English",
    "works": "Full-time",
    "farmingTypes": "Organic",
    "landArea": 50.5,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Wheat",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('4567538771', 'Abhishek', '7896543210', '1990-06-25', '{
    "highestEducation": "Master''s Degree",
    "maritalStatus": "Divorced",
    "typeOfHouse": "Cottage",
    "numberOfDependents": 1,
    "address": {
        "streetAddress": "234 River View Road",
        "addressLocality": "Harvest Springs",
        "addressRegion": "Western State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "German", "French"],
    "works": "Seasonal",
    "farmingTypes": ["Aquaculture", "Sedentary"],
    "landArea": 120.3,
    "landOwnershipType": "Leased",
    "primaryCropType": "Rice",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('4567538772', 'Alheri Bobby', '9876543210', '1985-10-25', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Ranch",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "789 Valley Lane",
        "addressLocality": "Greenfield",
        "addressRegion": "Midwest State",
        "postalCode": "67890",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "Spanish", "Portuguese"],
    "works": "Part-time",
    "farmingTypes": ["Nomadic", "Pastoral"],
    "landArea": 75.8,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Soybeans",
    "secondaryCropType": "Wheat"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('8267411572', 'John', '9753186520', '1987-03-20', '{
    "highestEducation": "Master''s Degree",
    "maritalStatus": "Divorced",
    "typeOfHouse": "Cottage",
    "numberOfDependents": 1,
    "address": {
        "streetAddress": "234 River View Road",
        "addressLocality": "Harvest Springs",
        "addressRegion": "Western State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "German", "French"],
    "works": "Seasonal",
    "farmingTypes": ["Aquaculture", "Sedentary"],
    "landArea": 120.3,
    "landOwnershipType": "Leased",
    "primaryCropType": "Rice",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('sEaaNFRcmPMxLM9Itv_iFqDkWthO2-kFGYA6btP6y8M', 'Doe', '6789012345', '1975-10-28', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Ranch",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "789 Valley Lane",
        "addressLocality": "Greenfield",
        "addressRegion": "Midwest State",
        "postalCode": "67890",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "Spanish", "Portuguese"],
    "works": "Part-time",
    "farmingTypes": ["Nomadic", "Pastoral"],
    "landArea": 75.8,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Soybeans",
    "secondaryCropType": "Wheat"
}');


--
-- PostgreSQL database dump complete
--

