package example;


// XMLInputFactory checks
class GoodXMLInputFactory {
    public void Blah() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
    }
}

class GoodConstXMLInputFactory {
    public void Blah() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        xmlInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    }
}

class BadXMLInputFactory {
    public Blah() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        xmlInputFactory.setProperty("javax.xml.stream.isSupportingExternalEntities", true);
    }
}

class MaybeBadXMLInputFactory {
    public Blah() {
        final XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
    }
}





// DocumentBuilderFactory checks
class GoodDocumentBuilderFactory {
    public void Blah() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all
        // XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
        dbf.setFeature(FEATURE, true);
    }
}


class GoodDocumentBuilderFactory_2 {
    public void Blah() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        // JDK7+ - http://xml.org/sax/features/external-general-entities
        //This feature has to be used together with the following one, otherwise it will not protect you from XXE for sure
         FEATURE = "http://xml.org/sax/features/external-general-entities";
         dbf.setFeature(FEATURE, false);
         // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
         // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
         // JDK7+ - http://xml.org/sax/features/external-parameter-entities
         //This feature has to be used together with the previous one, otherwise it will not protect you from XXE for sure
         FEATURE = "http://xml.org/sax/features/external-parameter-entities";
         dbf.setFeature(FEATURE, false);
    }
}


class BadDocumentBuilderFactory {
    public Blah() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        // Enable support to external DTDs 
        FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
        dbf.setFeature(FEATURE, true);
    }
}


class BadDocumentBuilderFactory_2 {
    public Blah() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        // Enable support to external DTDs 
        // per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
        dbf.setXIncludeAware(true);
        dbf.setExpandEntityReferences(true);
        // If for some reason support for inline DOCTYPEs are a requirement, then
        // ensure the entity settings are disabled (setXIncludeAware and setExpandEntityReferences should 
        // be set to false), but beware that SSRF attacks of service attacks (such as billion laughs 
        // or decompression bombs via "jar:") are a risk.
        // (http://cwe.mitre.org/data/definitions/918.html) and denial
    }
}

class MaybeDocumentBuilderFactory {
    public Blah() {
        // Possible XXE
        DocumentBuilderFactory dbf = new DocumentBuilderFactory();
        String FEATURE = null;
    }
}





// XMLReader checks
class GoodXMLReaderFactory {
    public void Blah() {
        XMLReader xr = XMLReaderFactory.createXMLReader();
        // Disable support to external DTDs
        xr.setFeature("http://xml.org/sax/features/external-general-entities", false);
        xr.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        xr.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        xr.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }
}


class BadXMLReaderFactory {
    public Blah() {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser saxParser = spf.newSAXParser();
        XMLReader xr = saxParser.getXMLReader();
        // Enable support to external DTDs
        xr.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    }
}


class MaybeBadXMLReaderFactory {
    public Blah() {
        // Possible XXE
        XMLReader xr = XMLReaderFactory.createXMLReader();
    }
}
