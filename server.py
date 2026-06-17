"""
IP Inspector - Self-contained backend
Sources used (NO third-party HTTP APIs):
  - MaxMind GeoLite2-City.mmdb  (bundled local DB) -> geo, city, timezone, lat/lng, postal
  - Team Cymru DNS              (DNS TXT queries)   -> ASN number, CIDR network, org name
  - Python socket stdlib        (reverse DNS)       -> hostname
  - pycountry                   (ISO data)          -> alpha3, official name, flag
  - Built-in dataset            (country extras)    -> capital, TLD, calling code,
                                                       currency, languages, area, population
"""

import socket
import struct
import ipaddress
import json
import re
import datetime
import os

import maxminddb
import dns.resolver
import pycountry
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static")

# ---------------------------------------------------------------------------
# Path to bundled GeoLite2 DB (installed via maxminddb-geolite2 pip package)
# ---------------------------------------------------------------------------
MMDB_PATH = "/usr/local/lib/python3.12/dist-packages/_maxminddb_geolite2/GeoLite2-City.mmdb"

# ---------------------------------------------------------------------------
# Static country metadata  (capitals, TLDs, calling codes, currencies,
# languages, area km², population)
# Sources: ISO 3166, ITU-T E.164, UN data  -  embedded directly, no HTTP.
# ---------------------------------------------------------------------------
COUNTRY_DATA = {
    "AD": {"capital":"Andorra la Vella","tld":".ad","calling_code":"+376","currency":"EUR","currency_name":"Euro","languages":"ca","area":468,"population":77142},
    "AE": {"capital":"Abu Dhabi","tld":".ae","calling_code":"+971","currency":"AED","currency_name":"UAE Dirham","languages":"ar","area":83600,"population":9890402},
    "AF": {"capital":"Kabul","tld":".af","calling_code":"+93","currency":"AFN","currency_name":"Afghan Afghani","languages":"ps,uz,tk","area":652230,"population":38928346},
    "AG": {"capital":"Saint John's","tld":".ag","calling_code":"+1-268","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":442,"population":97929},
    "AL": {"capital":"Tirana","tld":".al","calling_code":"+355","currency":"ALL","currency_name":"Albanian Lek","languages":"sq","area":28748,"population":2877797},
    "AM": {"capital":"Yerevan","tld":".am","calling_code":"+374","currency":"AMD","currency_name":"Armenian Dram","languages":"hy","area":29743,"population":2963243},
    "AO": {"capital":"Luanda","tld":".ao","calling_code":"+244","currency":"AOA","currency_name":"Angolan Kwanza","languages":"pt","area":1246700,"population":32866272},
    "AR": {"capital":"Buenos Aires","tld":".ar","calling_code":"+54","currency":"ARS","currency_name":"Argentine Peso","languages":"es,gn","area":2780400,"population":45195777},
    "AT": {"capital":"Vienna","tld":".at","calling_code":"+43","currency":"EUR","currency_name":"Euro","languages":"de","area":83871,"population":9006398},
    "AU": {"capital":"Canberra","tld":".au","calling_code":"+61","currency":"AUD","currency_name":"Australian Dollar","languages":"en","area":7692024,"population":25499884},
    "AZ": {"capital":"Baku","tld":".az","calling_code":"+994","currency":"AZN","currency_name":"Azerbaijani Manat","languages":"az","area":86600,"population":10139177},
    "BA": {"capital":"Sarajevo","tld":".ba","calling_code":"+387","currency":"BAM","currency_name":"Bosnia-Herzegovina Convertible Mark","languages":"bs,hr,sr","area":51197,"population":3280819},
    "BB": {"capital":"Bridgetown","tld":".bb","calling_code":"+1-246","currency":"BBD","currency_name":"Barbadian Dollar","languages":"en","area":430,"population":287375},
    "BD": {"capital":"Dhaka","tld":".bd","calling_code":"+880","currency":"BDT","currency_name":"Bangladeshi Taka","languages":"bn","area":147570,"population":164689383},
    "BE": {"capital":"Brussels","tld":".be","calling_code":"+32","currency":"EUR","currency_name":"Euro","languages":"nl,fr,de","area":30528,"population":11589623},
    "BF": {"capital":"Ouagadougou","tld":".bf","calling_code":"+226","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":274222,"population":20903273},
    "BG": {"capital":"Sofia","tld":".bg","calling_code":"+359","currency":"BGN","currency_name":"Bulgarian Lev","languages":"bg","area":110879,"population":6948445},
    "BH": {"capital":"Manama","tld":".bh","calling_code":"+973","currency":"BHD","currency_name":"Bahraini Dinar","languages":"ar","area":765,"population":1701575},
    "BI": {"capital":"Gitega","tld":".bi","calling_code":"+257","currency":"BIF","currency_name":"Burundian Franc","languages":"fr,rn","area":27830,"population":11890784},
    "BJ": {"capital":"Porto-Novo","tld":".bj","calling_code":"+229","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":112622,"population":12123200},
    "BN": {"capital":"Bandar Seri Begawan","tld":".bn","calling_code":"+673","currency":"BND","currency_name":"Brunei Dollar","languages":"ms","area":5765,"population":437479},
    "BO": {"capital":"Sucre","tld":".bo","calling_code":"+591","currency":"BOB","currency_name":"Bolivian Boliviano","languages":"es,qu,ay","area":1098581,"population":11673021},
    "BR": {"capital":"Brasília","tld":".br","calling_code":"+55","currency":"BRL","currency_name":"Brazilian Real","languages":"pt","area":8515767,"population":212559417},
    "BS": {"capital":"Nassau","tld":".bs","calling_code":"+1-242","currency":"BSD","currency_name":"Bahamian Dollar","languages":"en","area":13943,"population":393244},
    "BT": {"capital":"Thimphu","tld":".bt","calling_code":"+975","currency":"BTN","currency_name":"Bhutanese Ngultrum","languages":"dz","area":38394,"population":771608},
    "BW": {"capital":"Gaborone","tld":".bw","calling_code":"+267","currency":"BWP","currency_name":"Botswanan Pula","languages":"en,tn","area":581730,"population":2351627},
    "BY": {"capital":"Minsk","tld":".by","calling_code":"+375","currency":"BYR","currency_name":"Belarusian Ruble","languages":"be,ru","area":207600,"population":9449323},
    "BZ": {"capital":"Belmopan","tld":".bz","calling_code":"+501","currency":"BZD","currency_name":"Belize Dollar","languages":"en,es","area":22966,"population":397628},
    "CA": {"capital":"Ottawa","tld":".ca","calling_code":"+1","currency":"CAD","currency_name":"Canadian Dollar","languages":"en,fr","area":9984670,"population":37742154},
    "CD": {"capital":"Kinshasa","tld":".cd","calling_code":"+243","currency":"CDF","currency_name":"Congolese Franc","languages":"fr,ln,kg,sw,lu","area":2344858,"population":89561403},
    "CF": {"capital":"Bangui","tld":".cf","calling_code":"+236","currency":"XAF","currency_name":"Central African CFA Franc","languages":"fr,sg","area":622984,"population":4829767},
    "CG": {"capital":"Brazzaville","tld":".cg","calling_code":"+242","currency":"XAF","currency_name":"Central African CFA Franc","languages":"fr,kg","area":342000,"population":5518087},
    "CH": {"capital":"Bern","tld":".ch","calling_code":"+41","currency":"CHF","currency_name":"Swiss Franc","languages":"de,fr,it","area":41285,"population":8654622},
    "CI": {"capital":"Yamoussoukro","tld":".ci","calling_code":"+225","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":322463,"population":26378274},
    "CL": {"capital":"Santiago","tld":".cl","calling_code":"+56","currency":"CLP","currency_name":"Chilean Peso","languages":"es","area":756102,"population":19116201},
    "CM": {"capital":"Yaoundé","tld":".cm","calling_code":"+237","currency":"XAF","currency_name":"Central African CFA Franc","languages":"en,fr","area":475442,"population":26545863},
    "CN": {"capital":"Beijing","tld":".cn","calling_code":"+86","currency":"CNY","currency_name":"Chinese Yuan","languages":"zh","area":9596960,"population":1439323776},
    "CO": {"capital":"Bogotá","tld":".co","calling_code":"+57","currency":"COP","currency_name":"Colombian Peso","languages":"es","area":1141748,"population":50882891},
    "CR": {"capital":"San José","tld":".cr","calling_code":"+506","currency":"CRC","currency_name":"Costa Rican Colón","languages":"es","area":51100,"population":5094118},
    "CU": {"capital":"Havana","tld":".cu","calling_code":"+53","currency":"CUP","currency_name":"Cuban Peso","languages":"es","area":109884,"population":11326616},
    "CV": {"capital":"Praia","tld":".cv","calling_code":"+238","currency":"CVE","currency_name":"Cape Verdean Escudo","languages":"pt","area":4033,"population":555987},
    "CY": {"capital":"Nicosia","tld":".cy","calling_code":"+357","currency":"EUR","currency_name":"Euro","languages":"el,tr","area":9251,"population":1207359},
    "CZ": {"capital":"Prague","tld":".cz","calling_code":"+420","currency":"CZK","currency_name":"Czech Koruna","languages":"cs","area":78866,"population":10708981},
    "DE": {"capital":"Berlin","tld":".de","calling_code":"+49","currency":"EUR","currency_name":"Euro","languages":"de","area":357114,"population":83783942},
    "DJ": {"capital":"Djibouti","tld":".dj","calling_code":"+253","currency":"DJF","currency_name":"Djiboutian Franc","languages":"fr,ar","area":23200,"population":988000},
    "DK": {"capital":"Copenhagen","tld":".dk","calling_code":"+45","currency":"DKK","currency_name":"Danish Krone","languages":"da","area":43094,"population":5792202},
    "DM": {"capital":"Roseau","tld":".dm","calling_code":"+1-767","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":751,"population":71986},
    "DO": {"capital":"Santo Domingo","tld":".do","calling_code":"+1-809","currency":"DOP","currency_name":"Dominican Peso","languages":"es","area":48671,"population":10847910},
    "DZ": {"capital":"Algiers","tld":".dz","calling_code":"+213","currency":"DZD","currency_name":"Algerian Dinar","languages":"ar","area":2381741,"population":43851044},
    "EC": {"capital":"Quito","tld":".ec","calling_code":"+593","currency":"USD","currency_name":"US Dollar","languages":"es","area":283561,"population":17643054},
    "EE": {"capital":"Tallinn","tld":".ee","calling_code":"+372","currency":"EUR","currency_name":"Euro","languages":"et","area":45228,"population":1326535},
    "EG": {"capital":"Cairo","tld":".eg","calling_code":"+20","currency":"EGP","currency_name":"Egyptian Pound","languages":"ar","area":1001449,"population":102334404},
    "ER": {"capital":"Asmara","tld":".er","calling_code":"+291","currency":"ERN","currency_name":"Eritrean Nakfa","languages":"ti,ar,en","area":117600,"population":3546421},
    "ES": {"capital":"Madrid","tld":".es","calling_code":"+34","currency":"EUR","currency_name":"Euro","languages":"es","area":505990,"population":46754778},
    "ET": {"capital":"Addis Ababa","tld":".et","calling_code":"+251","currency":"ETB","currency_name":"Ethiopian Birr","languages":"am","area":1104300,"population":114963588},
    "FI": {"capital":"Helsinki","tld":".fi","calling_code":"+358","currency":"EUR","currency_name":"Euro","languages":"fi,sv","area":338424,"population":5540720},
    "FJ": {"capital":"Suva","tld":".fj","calling_code":"+679","currency":"FJD","currency_name":"Fijian Dollar","languages":"en,fj","area":18274,"population":896445},
    "FM": {"capital":"Palikir","tld":".fm","calling_code":"+691","currency":"USD","currency_name":"US Dollar","languages":"en","area":702,"population":115023},
    "FR": {"capital":"Paris","tld":".fr","calling_code":"+33","currency":"EUR","currency_name":"Euro","languages":"fr","area":551695,"population":65273511},
    "GA": {"capital":"Libreville","tld":".ga","calling_code":"+241","currency":"XAF","currency_name":"Central African CFA Franc","languages":"fr","area":267668,"population":2225734},
    "GB": {"capital":"London","tld":".co.uk","calling_code":"+44","currency":"GBP","currency_name":"British Pound Sterling","languages":"en","area":242900,"population":67886011},
    "GD": {"capital":"Saint George's","tld":".gd","calling_code":"+1-473","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":344,"population":112523},
    "GE": {"capital":"Tbilisi","tld":".ge","calling_code":"+995","currency":"GEL","currency_name":"Georgian Lari","languages":"ka","area":69700,"population":3989167},
    "GH": {"capital":"Accra","tld":".gh","calling_code":"+233","currency":"GHS","currency_name":"Ghanaian Cedi","languages":"en","area":238533,"population":31072940},
    "GM": {"capital":"Banjul","tld":".gm","calling_code":"+220","currency":"GMD","currency_name":"Gambian Dalasi","languages":"en","area":11295,"population":2416668},
    "GN": {"capital":"Conakry","tld":".gn","calling_code":"+224","currency":"GNF","currency_name":"Guinean Franc","languages":"fr","area":245857,"population":13132795},
    "GQ": {"capital":"Malabo","tld":".gq","calling_code":"+240","currency":"XAF","currency_name":"Central African CFA Franc","languages":"es,fr","area":28051,"population":1402985},
    "GR": {"capital":"Athens","tld":".gr","calling_code":"+30","currency":"EUR","currency_name":"Euro","languages":"el","area":131957,"population":10423054},
    "GT": {"capital":"Guatemala City","tld":".gt","calling_code":"+502","currency":"GTQ","currency_name":"Guatemalan Quetzal","languages":"es","area":108889,"population":17915568},
    "GW": {"capital":"Bissau","tld":".gw","calling_code":"+245","currency":"XOF","currency_name":"West African CFA Franc","languages":"pt","area":36125,"population":1968001},
    "GY": {"capital":"Georgetown","tld":".gy","calling_code":"+592","currency":"GYD","currency_name":"Guyanese Dollar","languages":"en","area":214969,"population":786552},
    "HN": {"capital":"Tegucigalpa","tld":".hn","calling_code":"+504","currency":"HNL","currency_name":"Honduran Lempira","languages":"es","area":112492,"population":9904607},
    "HR": {"capital":"Zagreb","tld":".hr","calling_code":"+385","currency":"EUR","currency_name":"Euro","languages":"hr","area":56594,"population":4105267},
    "HT": {"capital":"Port-au-Prince","tld":".ht","calling_code":"+509","currency":"HTG","currency_name":"Haitian Gourde","languages":"ht,fr","area":27750,"population":11402528},
    "HU": {"capital":"Budapest","tld":".hu","calling_code":"+36","currency":"HUF","currency_name":"Hungarian Forint","languages":"hu","area":93028,"population":9660351},
    "ID": {"capital":"Jakarta","tld":".id","calling_code":"+62","currency":"IDR","currency_name":"Indonesian Rupiah","languages":"id","area":1904569,"population":273523615},
    "IE": {"capital":"Dublin","tld":".ie","calling_code":"+353","currency":"EUR","currency_name":"Euro","languages":"en,ga","area":70273,"population":4937786},
    "IL": {"capital":"Jerusalem","tld":".il","calling_code":"+972","currency":"ILS","currency_name":"Israeli New Shekel","languages":"he,ar","area":20770,"population":8655535},
    "IN": {"capital":"New Delhi","tld":".in","calling_code":"+91","currency":"INR","currency_name":"Indian Rupee","languages":"hi,en","area":3287263,"population":1380004385},
    "IQ": {"capital":"Baghdad","tld":".iq","calling_code":"+964","currency":"IQD","currency_name":"Iraqi Dinar","languages":"ar,ku","area":438317,"population":40222493},
    "IR": {"capital":"Tehran","tld":".ir","calling_code":"+98","currency":"IRR","currency_name":"Iranian Rial","languages":"fa","area":1648195,"population":83992949},
    "IS": {"capital":"Reykjavik","tld":".is","calling_code":"+354","currency":"ISK","currency_name":"Icelandic Króna","languages":"is","area":103000,"population":341243},
    "IT": {"capital":"Rome","tld":".it","calling_code":"+39","currency":"EUR","currency_name":"Euro","languages":"it","area":301336,"population":60461826},
    "JM": {"capital":"Kingston","tld":".jm","calling_code":"+1-876","currency":"JMD","currency_name":"Jamaican Dollar","languages":"en","area":10991,"population":2961167},
    "JO": {"capital":"Amman","tld":".jo","calling_code":"+962","currency":"JOD","currency_name":"Jordanian Dinar","languages":"ar","area":89342,"population":10203134},
    "JP": {"capital":"Tokyo","tld":".jp","calling_code":"+81","currency":"JPY","currency_name":"Japanese Yen","languages":"ja","area":377930,"population":126476461},
    "KE": {"capital":"Nairobi","tld":".ke","calling_code":"+254","currency":"KES","currency_name":"Kenyan Shilling","languages":"en,sw","area":580367,"population":53771296},
    "KG": {"capital":"Bishkek","tld":".kg","calling_code":"+996","currency":"KGS","currency_name":"Kyrgyzstani Som","languages":"ky,ru","area":199951,"population":6524195},
    "KH": {"capital":"Phnom Penh","tld":".kh","calling_code":"+855","currency":"KHR","currency_name":"Cambodian Riel","languages":"km","area":181035,"population":16718965},
    "KI": {"capital":"South Tarawa","tld":".ki","calling_code":"+686","currency":"AUD","currency_name":"Australian Dollar","languages":"en","area":811,"population":119449},
    "KM": {"capital":"Moroni","tld":".km","calling_code":"+269","currency":"KMF","currency_name":"Comorian Franc","languages":"ar,fr","area":2235,"population":869601},
    "KN": {"capital":"Basseterre","tld":".kn","calling_code":"+1-869","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":261,"population":53199},
    "KP": {"capital":"Pyongyang","tld":".kp","calling_code":"+850","currency":"KPW","currency_name":"North Korean Won","languages":"ko","area":120538,"population":25778816},
    "KR": {"capital":"Seoul","tld":".kr","calling_code":"+82","currency":"KRW","currency_name":"South Korean Won","languages":"ko","area":100210,"population":51269185},
    "KW": {"capital":"Kuwait City","tld":".kw","calling_code":"+965","currency":"KWD","currency_name":"Kuwaiti Dinar","languages":"ar","area":17818,"population":4270571},
    "KZ": {"capital":"Nur-Sultan","tld":".kz","calling_code":"+7","currency":"KZT","currency_name":"Kazakhstani Tenge","languages":"kk,ru","area":2724900,"population":18776707},
    "LA": {"capital":"Vientiane","tld":".la","calling_code":"+856","currency":"LAK","currency_name":"Laotian Kip","languages":"lo","area":236800,"population":7275560},
    "LB": {"capital":"Beirut","tld":".lb","calling_code":"+961","currency":"LBP","currency_name":"Lebanese Pound","languages":"ar,fr","area":10400,"population":6825445},
    "LC": {"capital":"Castries","tld":".lc","calling_code":"+1-758","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":616,"population":183627},
    "LI": {"capital":"Vaduz","tld":".li","calling_code":"+423","currency":"CHF","currency_name":"Swiss Franc","languages":"de","area":160,"population":38128},
    "LK": {"capital":"Sri Jayawardenepura Kotte","tld":".lk","calling_code":"+94","currency":"LKR","currency_name":"Sri Lankan Rupee","languages":"si,ta","area":65610,"population":21413249},
    "LR": {"capital":"Monrovia","tld":".lr","calling_code":"+231","currency":"LRD","currency_name":"Liberian Dollar","languages":"en","area":111369,"population":5057681},
    "LS": {"capital":"Maseru","tld":".ls","calling_code":"+266","currency":"LSL","currency_name":"Lesotho Loti","languages":"en,st","area":30355,"population":2142249},
    "LT": {"capital":"Vilnius","tld":".lt","calling_code":"+370","currency":"EUR","currency_name":"Euro","languages":"lt","area":65300,"population":2722289},
    "LU": {"capital":"Luxembourg","tld":".lu","calling_code":"+352","currency":"EUR","currency_name":"Euro","languages":"lb,de,fr","area":2586,"population":625978},
    "LV": {"capital":"Riga","tld":".lv","calling_code":"+371","currency":"EUR","currency_name":"Euro","languages":"lv","area":64589,"population":1886198},
    "LY": {"capital":"Tripoli","tld":".ly","calling_code":"+218","currency":"LYD","currency_name":"Libyan Dinar","languages":"ar","area":1759540,"population":6871292},
    "MA": {"capital":"Rabat","tld":".ma","calling_code":"+212","currency":"MAD","currency_name":"Moroccan Dirham","languages":"ar","area":446550,"population":36910560},
    "MC": {"capital":"Monaco","tld":".mc","calling_code":"+377","currency":"EUR","currency_name":"Euro","languages":"fr","area":2,"population":39242},
    "MD": {"capital":"Chisinau","tld":".md","calling_code":"+373","currency":"MDL","currency_name":"Moldovan Leu","languages":"ro","area":33846,"population":4033963},
    "ME": {"capital":"Podgorica","tld":".me","calling_code":"+382","currency":"EUR","currency_name":"Euro","languages":"sr","area":13812,"population":628066},
    "MG": {"capital":"Antananarivo","tld":".mg","calling_code":"+261","currency":"MGA","currency_name":"Malagasy Ariary","languages":"fr,mg","area":587041,"population":27691018},
    "MH": {"capital":"Majuro","tld":".mh","calling_code":"+692","currency":"USD","currency_name":"US Dollar","languages":"en,mh","area":181,"population":59190},
    "MK": {"capital":"Skopje","tld":".mk","calling_code":"+389","currency":"MKD","currency_name":"Macedonian Denar","languages":"mk","area":25713,"population":2083374},
    "ML": {"capital":"Bamako","tld":".ml","calling_code":"+223","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":1240192,"population":20250833},
    "MM": {"capital":"Naypyidaw","tld":".mm","calling_code":"+95","currency":"MMK","currency_name":"Myanmar Kyat","languages":"my","area":676578,"population":54409800},
    "MN": {"capital":"Ulaanbaatar","tld":".mn","calling_code":"+976","currency":"MNT","currency_name":"Mongolian Tögrög","languages":"mn","area":1564116,"population":3278292},
    "MR": {"capital":"Nouakchott","tld":".mr","calling_code":"+222","currency":"MRO","currency_name":"Mauritanian Ouguiya","languages":"ar","area":1030700,"population":4649658},
    "MT": {"capital":"Valletta","tld":".mt","calling_code":"+356","currency":"EUR","currency_name":"Euro","languages":"mt,en","area":316,"population":441543},
    "MU": {"capital":"Port Louis","tld":".mu","calling_code":"+230","currency":"MUR","currency_name":"Mauritian Rupee","languages":"en","area":2040,"population":1271768},
    "MV": {"capital":"Malé","tld":".mv","calling_code":"+960","currency":"MVR","currency_name":"Maldivian Rufiyaa","languages":"dv","area":298,"population":540544},
    "MW": {"capital":"Lilongwe","tld":".mw","calling_code":"+265","currency":"MWK","currency_name":"Malawian Kwacha","languages":"en,ny","area":118484,"population":19129952},
    "MX": {"capital":"Mexico City","tld":".mx","calling_code":"+52","currency":"MXN","currency_name":"Mexican Peso","languages":"es","area":1964375,"population":128932753},
    "MY": {"capital":"Kuala Lumpur","tld":".my","calling_code":"+60","currency":"MYR","currency_name":"Malaysian Ringgit","languages":"ms","area":329847,"population":32365999},
    "MZ": {"capital":"Maputo","tld":".mz","calling_code":"+258","currency":"MZN","currency_name":"Mozambican Metical","languages":"pt","area":801590,"population":31255435},
    "NA": {"capital":"Windhoek","tld":".na","calling_code":"+264","currency":"NAD","currency_name":"Namibian Dollar","languages":"en","area":824292,"population":2540905},
    "NE": {"capital":"Niamey","tld":".ne","calling_code":"+227","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":1267000,"population":24206644},
    "NG": {"capital":"Abuja","tld":".ng","calling_code":"+234","currency":"NGN","currency_name":"Nigerian Naira","languages":"en","area":923768,"population":206139589},
    "NI": {"capital":"Managua","tld":".ni","calling_code":"+505","currency":"NIO","currency_name":"Nicaraguan Córdoba","languages":"es","area":130373,"population":6624554},
    "NL": {"capital":"Amsterdam","tld":".nl","calling_code":"+31","currency":"EUR","currency_name":"Euro","languages":"nl","area":41543,"population":17134872},
    "NO": {"capital":"Oslo","tld":".no","calling_code":"+47","currency":"NOK","currency_name":"Norwegian Krone","languages":"no,nb,nn","area":323802,"population":5421241},
    "NP": {"capital":"Kathmandu","tld":".np","calling_code":"+977","currency":"NPR","currency_name":"Nepalese Rupee","languages":"ne","area":147181,"population":29136808},
    "NR": {"capital":"Yaren","tld":".nr","calling_code":"+674","currency":"AUD","currency_name":"Australian Dollar","languages":"en,na","area":21,"population":10824},
    "NZ": {"capital":"Wellington","tld":".nz","calling_code":"+64","currency":"NZD","currency_name":"New Zealand Dollar","languages":"en,mi","area":270467,"population":4822233},
    "OM": {"capital":"Muscat","tld":".om","calling_code":"+968","currency":"OMR","currency_name":"Omani Rial","languages":"ar","area":309500,"population":4974986},
    "PA": {"capital":"Panama City","tld":".pa","calling_code":"+507","currency":"PAB","currency_name":"Panamanian Balboa","languages":"es","area":75417,"population":4314767},
    "PE": {"capital":"Lima","tld":".pe","calling_code":"+51","currency":"PEN","currency_name":"Peruvian Sol","languages":"es,qu,ay","area":1285216,"population":32971854},
    "PG": {"capital":"Port Moresby","tld":".pg","calling_code":"+675","currency":"PGK","currency_name":"Papua New Guinean Kina","languages":"en","area":462840,"population":8947024},
    "PH": {"capital":"Manila","tld":".ph","calling_code":"+63","currency":"PHP","currency_name":"Philippine Peso","languages":"en,tl","area":300000,"population":109581078},
    "PK": {"capital":"Islamabad","tld":".pk","calling_code":"+92","currency":"PKR","currency_name":"Pakistani Rupee","languages":"ur,en","area":881913,"population":220892340},
    "PL": {"capital":"Warsaw","tld":".pl","calling_code":"+48","currency":"PLN","currency_name":"Polish Złoty","languages":"pl","area":312679,"population":37846611},
    "PT": {"capital":"Lisbon","tld":".pt","calling_code":"+351","currency":"EUR","currency_name":"Euro","languages":"pt","area":92212,"population":10196709},
    "PW": {"capital":"Ngerulmud","tld":".pw","calling_code":"+680","currency":"USD","currency_name":"US Dollar","languages":"en","area":459,"population":18094},
    "PY": {"capital":"Asunción","tld":".py","calling_code":"+595","currency":"PYG","currency_name":"Paraguayan Guaraní","languages":"es,gn","area":406752,"population":7132538},
    "QA": {"capital":"Doha","tld":".qa","calling_code":"+974","currency":"QAR","currency_name":"Qatari Riyal","languages":"ar","area":11586,"population":2881053},
    "RO": {"capital":"Bucharest","tld":".ro","calling_code":"+40","currency":"RON","currency_name":"Romanian Leu","languages":"ro","area":238397,"population":19237691},
    "RS": {"capital":"Belgrade","tld":".rs","calling_code":"+381","currency":"RSD","currency_name":"Serbian Dinar","languages":"sr","area":77474,"population":8737371},
    "RU": {"capital":"Moscow","tld":".ru","calling_code":"+7","currency":"RUB","currency_name":"Russian Ruble","languages":"ru","area":17098242,"population":145934462},
    "RW": {"capital":"Kigali","tld":".rw","calling_code":"+250","currency":"RWF","currency_name":"Rwandan Franc","languages":"rw,en,fr","area":26338,"population":12952218},
    "SA": {"capital":"Riyadh","tld":".sa","calling_code":"+966","currency":"SAR","currency_name":"Saudi Riyal","languages":"ar","area":2149690,"population":34813871},
    "SB": {"capital":"Honiara","tld":".sb","calling_code":"+677","currency":"SBD","currency_name":"Solomon Islands Dollar","languages":"en","area":28896,"population":686884},
    "SC": {"capital":"Victoria","tld":".sc","calling_code":"+248","currency":"SCR","currency_name":"Seychellois Rupee","languages":"fr,en","area":452,"population":98347},
    "SD": {"capital":"Khartoum","tld":".sd","calling_code":"+249","currency":"SDG","currency_name":"Sudanese Pound","languages":"ar,en","area":1861484,"population":43849260},
    "SE": {"capital":"Stockholm","tld":".se","calling_code":"+46","currency":"SEK","currency_name":"Swedish Krona","languages":"sv","area":450295,"population":10099265},
    "SG": {"capital":"Singapore","tld":".sg","calling_code":"+65","currency":"SGD","currency_name":"Singapore Dollar","languages":"en,ms,ta,zh","area":710,"population":5850342},
    "SI": {"capital":"Ljubljana","tld":".si","calling_code":"+386","currency":"EUR","currency_name":"Euro","languages":"sl","area":20273,"population":2078938},
    "SK": {"capital":"Bratislava","tld":".sk","calling_code":"+421","currency":"EUR","currency_name":"Euro","languages":"sk","area":49035,"population":5459642},
    "SL": {"capital":"Freetown","tld":".sl","calling_code":"+232","currency":"SLL","currency_name":"Sierra Leonean Leone","languages":"en","area":71740,"population":7976983},
    "SM": {"capital":"San Marino","tld":".sm","calling_code":"+378","currency":"EUR","currency_name":"Euro","languages":"it","area":61,"population":33931},
    "SN": {"capital":"Dakar","tld":".sn","calling_code":"+221","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":196722,"population":16743927},
    "SO": {"capital":"Mogadishu","tld":".so","calling_code":"+252","currency":"SOS","currency_name":"Somali Shilling","languages":"so,ar","area":637657,"population":15893222},
    "SR": {"capital":"Paramaribo","tld":".sr","calling_code":"+597","currency":"SRD","currency_name":"Surinamese Dollar","languages":"nl","area":163820,"population":586632},
    "SS": {"capital":"Juba","tld":".ss","calling_code":"+211","currency":"SSP","currency_name":"South Sudanese Pound","languages":"en","area":619745,"population":11193725},
    "ST": {"capital":"São Tomé","tld":".st","calling_code":"+239","currency":"STD","currency_name":"São Tomé & Príncipe Dobra","languages":"pt","area":964,"population":219159},
    "SV": {"capital":"San Salvador","tld":".sv","calling_code":"+503","currency":"USD","currency_name":"US Dollar","languages":"es","area":21041,"population":6486205},
    "SY": {"capital":"Damascus","tld":".sy","calling_code":"+963","currency":"SYP","currency_name":"Syrian Pound","languages":"ar","area":185180,"population":17500658},
    "SZ": {"capital":"Mbabane","tld":".sz","calling_code":"+268","currency":"SZL","currency_name":"Swazi Lilangeni","languages":"en,ss","area":17364,"population":1160164},
    "TD": {"capital":"N'Djamena","tld":".td","calling_code":"+235","currency":"XAF","currency_name":"Central African CFA Franc","languages":"fr,ar","area":1284000,"population":16425864},
    "TG": {"capital":"Lomé","tld":".tg","calling_code":"+228","currency":"XOF","currency_name":"West African CFA Franc","languages":"fr","area":56785,"population":8278724},
    "TH": {"capital":"Bangkok","tld":".th","calling_code":"+66","currency":"THB","currency_name":"Thai Baht","languages":"th","area":513120,"population":69799978},
    "TJ": {"capital":"Dushanbe","tld":".tj","calling_code":"+992","currency":"TJS","currency_name":"Tajikistani Somoni","languages":"tg,ru","area":143100,"population":9537645},
    "TL": {"capital":"Dili","tld":".tl","calling_code":"+670","currency":"USD","currency_name":"US Dollar","languages":"pt","area":14874,"population":1318445},
    "TM": {"capital":"Ashgabat","tld":".tm","calling_code":"+993","currency":"TMT","currency_name":"Turkmenistani Manat","languages":"tk","area":488100,"population":6031200},
    "TN": {"capital":"Tunis","tld":".tn","calling_code":"+216","currency":"TND","currency_name":"Tunisian Dinar","languages":"ar","area":163610,"population":11818619},
    "TO": {"capital":"Nuku'alofa","tld":".to","calling_code":"+676","currency":"TOP","currency_name":"Tongan Paʻanga","languages":"en,to","area":747,"population":105695},
    "TR": {"capital":"Ankara","tld":".tr","calling_code":"+90","currency":"TRY","currency_name":"Turkish Lira","languages":"tr","area":783562,"population":84339067},
    "TT": {"capital":"Port of Spain","tld":".tt","calling_code":"+1-868","currency":"TTD","currency_name":"Trinidad & Tobago Dollar","languages":"en","area":5128,"population":1399488},
    "TV": {"capital":"Funafuti","tld":".tv","calling_code":"+688","currency":"AUD","currency_name":"Australian Dollar","languages":"en","area":26,"population":11792},
    "TZ": {"capital":"Dodoma","tld":".tz","calling_code":"+255","currency":"TZS","currency_name":"Tanzanian Shilling","languages":"sw,en","area":945087,"population":59734218},
    "UA": {"capital":"Kyiv","tld":".ua","calling_code":"+380","currency":"UAH","currency_name":"Ukrainian Hryvnia","languages":"uk","area":603550,"population":43733762},
    "UG": {"capital":"Kampala","tld":".ug","calling_code":"+256","currency":"UGX","currency_name":"Ugandan Shilling","languages":"en,sw","area":241038,"population":45741007},
    "US": {"capital":"Washington, D.C.","tld":".us","calling_code":"+1","currency":"USD","currency_name":"US Dollar","languages":"en","area":9372610,"population":331002651},
    "UY": {"capital":"Montevideo","tld":".uy","calling_code":"+598","currency":"UYU","currency_name":"Uruguayan Peso","languages":"es","area":176215,"population":3473730},
    "UZ": {"capital":"Tashkent","tld":".uz","calling_code":"+998","currency":"UZS","currency_name":"Uzbekistani Som","languages":"uz","area":448978,"population":33469203},
    "VA": {"capital":"Vatican City","tld":".va","calling_code":"+379","currency":"EUR","currency_name":"Euro","languages":"it,la","area":1,"population":801},
    "VC": {"capital":"Kingstown","tld":".vc","calling_code":"+1-784","currency":"XCD","currency_name":"East Caribbean Dollar","languages":"en","area":389,"population":110940},
    "VE": {"capital":"Caracas","tld":".ve","calling_code":"+58","currency":"VEF","currency_name":"Venezuelan Bolívar","languages":"es","area":916445,"population":28435943},
    "VN": {"capital":"Hanoi","tld":".vn","calling_code":"+84","currency":"VND","currency_name":"Vietnamese Đồng","languages":"vi","area":331212,"population":97338579},
    "VU": {"capital":"Port Vila","tld":".vu","calling_code":"+678","currency":"VUV","currency_name":"Vanuatu Vatu","languages":"bi,en,fr","area":12189,"population":307145},
    "WS": {"capital":"Apia","tld":".ws","calling_code":"+685","currency":"WST","currency_name":"Samoan Tālā","languages":"sm,en","area":2842,"population":198414},
    "YE": {"capital":"Sana'a","tld":".ye","calling_code":"+967","currency":"YER","currency_name":"Yemeni Rial","languages":"ar","area":527968,"population":29825964},
    "ZA": {"capital":"Pretoria","tld":".za","calling_code":"+27","currency":"ZAR","currency_name":"South African Rand","languages":"zu,xh,af,nso,tn,en","area":1219090,"population":59308690},
    "ZM": {"capital":"Lusaka","tld":".zm","calling_code":"+260","currency":"ZMW","currency_name":"Zambian Kwacha","languages":"en","area":752618,"population":18383955},
    "ZW": {"capital":"Harare","tld":".zw","calling_code":"+263","currency":"ZWL","currency_name":"Zimbabwean Dollar","languages":"en,sn,nd","area":390757,"population":14862924},
}

# EU member states (as of 2024)
EU_MEMBERS = {
    "AT","BE","BG","CY","CZ","DE","DK","EE","ES","FI",
    "FR","GR","HR","HU","IE","IT","LT","LU","LV","MT",
    "NL","PL","PT","RO","SE","SI","SK"
}


def get_client_ip():
    """Get the real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def detect_ip_version(ip_str):
    """Return 'IPv4' or 'IPv6'."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return "IPv6" if addr.version == 6 else "IPv4"
    except Exception:
        return "IPv4"


def cymru_asn_lookup(ip_str):
    """
    Query Team Cymru's DNS-based ASN service.
    Returns dict with asn, network, org, country  or empty dict on failure.
    Pure DNS  —  no HTTP.
    """
    result = {}
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.version == 6:
            # expand to full hex, reverse nibbles
            expanded = addr.exploded.replace(":", "")
            reversed_nibbles = ".".join(reversed(expanded))
            origin_query = f"{reversed_nibbles}.origin6.asn.cymru.com"
        else:
            reversed_ip = ".".join(reversed(ip_str.split(".")))
            origin_query = f"{reversed_ip}.origin.asn.cymru.com"

        answers = dns.resolver.resolve(origin_query, "TXT", lifetime=5)
        raw = answers[0].to_text().strip('"')
        # Format: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) >= 2:
            result["asn"] = f"AS{parts[0].strip()}"
            result["network"] = parts[1].strip()

        # Now look up org name for the ASN number
        asn_num = parts[0].strip() if parts else None
        if asn_num:
            asn_query = f"AS{asn_num}.asn.cymru.com"
            try:
                asn_answers = dns.resolver.resolve(asn_query, "TXT", lifetime=5)
                asn_raw = asn_answers[0].to_text().strip('"')
                # Format: "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
                asn_parts = [p.strip() for p in asn_raw.split("|")]
                if len(asn_parts) >= 5:
                    org_full = asn_parts[4].strip()
                    result["org"] = f"AS{asn_num} {org_full}"
                elif len(asn_parts) >= 4:
                    result["org"] = asn_parts[-1].strip()
            except Exception:
                if "asn" in result:
                    result["org"] = result["asn"]
    except Exception:
        pass
    return result


def reverse_dns(ip_str):
    """Standard reverse DNS lookup via socket."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return ""


def geo_lookup(ip_str):
    """
    Look up city, region, country, lat/lng, timezone, postal
    from local GeoLite2-City.mmdb.
    """
    result = {}
    try:
        db = maxminddb.open_database(MMDB_PATH)
        data = db.get(ip_str)
        db.close()
        if not data:
            return result

        # City
        city_names = data.get("city", {}).get("names", {})
        result["city"] = city_names.get("en", "")

        # Subdivisions (region)
        subdivs = data.get("subdivisions", [])
        if subdivs:
            result["region"] = subdivs[0].get("names", {}).get("en", "")
            result["region_code"] = subdivs[0].get("iso_code", "")

        # Country
        country = data.get("country", {})
        result["country_code"] = country.get("iso_code", "")
        result["country_name"] = country.get("names", {}).get("en", "")
        result["in_eu"] = country.get("is_in_european_union", False)

        # Continent
        continent = data.get("continent", {})
        result["continent_code"] = continent.get("code", "")

        # Location
        loc = data.get("location", {})
        result["latitude"] = loc.get("latitude")
        result["longitude"] = loc.get("longitude")
        result["timezone"] = loc.get("time_zone", "")

        # Postal
        postal = data.get("postal", {})
        result["postal"] = postal.get("code", "")

    except Exception as e:
        app.logger.error(f"GeoLite2 error: {e}")
    return result


def utc_offset_from_timezone(tz_name):
    """Compute current UTC offset string like +0530 from a timezone name."""
    if not tz_name:
        return ""
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(tz_name)
        now = datetime.datetime.now(tz)
        offset = now.utcoffset()
        total_minutes = int(offset.total_seconds() // 60)
        sign = "+" if total_minutes >= 0 else "-"
        total_minutes = abs(total_minutes)
        hours, mins = divmod(total_minutes, 60)
        return f"{sign}{hours:02d}{mins:02d}"
    except Exception:
        return ""


def enrich_country(country_code):
    """Pull capital, TLD, calling code, currency, languages, area, population."""
    if not country_code:
        return {}
    result = {}

    # From our embedded dataset
    cd = COUNTRY_DATA.get(country_code, {})
    result["country_capital"]       = cd.get("capital", "")
    result["country_tld"]           = cd.get("tld", "")
    result["country_calling_code"]  = cd.get("calling_code", "")
    result["currency"]              = cd.get("currency", "")
    result["currency_name"]         = cd.get("currency_name", "")
    result["languages"]             = cd.get("languages", "")
    result["country_area"]          = cd.get("area", None)
    result["country_population"]    = cd.get("population", None)

    # ISO codes from pycountry
    try:
        c = pycountry.countries.get(alpha_2=country_code)
        if c:
            result["country_code_iso3"] = c.alpha_3
            result["country"] = country_code    # 2-letter kept as "country"
    except Exception:
        pass

    return result


@app.route("/api/ip")
def api_ip():
    ip = get_client_ip()

    payload = {
        "ip": ip,
        "network": "",
        "version": detect_ip_version(ip),
        "city": "",
        "region": "",
        "region_code": "",
        "country": "",
        "country_name": "",
        "country_code": "",
        "country_code_iso3": "",
        "country_capital": "",
        "country_tld": "",
        "continent_code": "",
        "in_eu": False,
        "postal": "",
        "latitude": None,
        "longitude": None,
        "timezone": "",
        "utc_offset": "",
        "country_calling_code": "",
        "currency": "",
        "currency_name": "",
        "languages": "",
        "country_area": None,
        "country_population": None,
        "asn": "",
        "org": "",
    }

    # 1. Geo lookup (local MMDB — no HTTP)
    geo = geo_lookup(ip)
    payload.update(geo)

    # 2. EU override from our own set if mmdb didn't catch it
    if payload["country_code"] and not payload["in_eu"]:
        payload["in_eu"] = payload["country_code"] in EU_MEMBERS

    # 3. Country enrichment from built-in dataset + pycountry
    country_extra = enrich_country(payload["country_code"])
    payload.update(country_extra)

    # 4. UTC offset derived from timezone (stdlib zoneinfo)
    if payload["timezone"]:
        payload["utc_offset"] = utc_offset_from_timezone(payload["timezone"])

    # 5. ASN + network + org via Cymru DNS (pure DNS, no HTTP API)
    cymru = cymru_asn_lookup(ip)
    payload.update(cymru)

    # 6. Reverse DNS hostname (stdlib socket)
    hostname = reverse_dns(ip)
    if hostname:
        payload["hostname"] = hostname

    return jsonify(payload)


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


if __name__ == "__main__":
    print("=" * 60)
    print("  IP Inspector — self-contained server")
    print("  Data sources:")
    print("    GeoLite2-City.mmdb  (bundled local database)")
    print("    Team Cymru DNS      (ASN/network via DNS TXT)")
    print("    Python socket       (reverse DNS)")
    print("    pycountry           (ISO 3166 codes)")
    print("    Built-in dataset    (capitals, TLDs, currencies)")
    print("  NO third-party HTTP APIs used.")
    print("=" * 60)
    print("  Open: http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
