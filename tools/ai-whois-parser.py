import time
import random

import httpx
from llama_index.core import PromptTemplate
from llama_index.llms.ollama import Ollama

import asyncwhois


def get_llm(model_name: str):
    # todo: adjust LLM params like temperature, etc.
    ollama_llm = Ollama(model_name, request_timeout=60.0)
    return ollama_llm


# todo: do prompt engineering! try few-shot examples?
PROMPT_TEMPLATE = """\
Below is the text output from a WHOIS server.
---------------------
{whois_text}
---------------------
Using the information contained in the text above and not prior knowledge, create a JSON formatted document
containing the information as keys and values. The JSON document should align with the following format where 
$VALUE is the value for the given key:
{{
    admin_address: $VALUE,
    admin_city: $VALUE,
    admin_country: $VALUE,
    admin_email: $VALUE,
    admin_fax: $VALUE,
    admin_id: $VALUE,
    admin_name: $VALUE,
    admin_organization: $VALUE,
    admin_phone: $VALUE,
    admin_state: $VALUE,
    admin_zipcode: $VALUE,
    billing_address: $VALUE,
    billing_city: $VALUE,
    billing_country: $VALUE,
    billing_email: $VALUE,
    billing_fax: $VALUE,
    billing_id: $VALUE,
    billing_name: $VALUE,
    billing_organization: $VALUE,
    billing_phone: $VALUE,
    billing_state: $VALUE,
    billing_zipcode: $VALUE,
    created: $VALUE,
    dnssec: $VALUE,
    domain_name: $VALUE,
    expires: $VALUE,
    name_servers: $VALUE,
    registrant_address: $VALUE,
    registrant_city: $VALUE,
    registrant_country: $VALUE,
    registrant_email: $VALUE,
    registrant_fax: $VALUE,
    registrant_name: $VALUE,
    registrant_organization: $VALUE,
    registrant_phone: $VALUE,
    registrant_state: $VALUE,
    registrant_zipcode: $VALUE,
    registrar: $VALUE,
    registrar_abuse_email: $VALUE,
    registrar_abuse_phone: $VALUE,
    registrar_iana_id: $VALUE,
    registrar_url: $VALUE,
    status: [$VALUE],
    tech_address: $VALUE,
    tech_city: $VALUE,
    tech_country: $VALUE,
    tech_email: $VALUE,
    tech_fax: $VALUE,
    tech_id: $VALUE,
    tech_name: $VALUE,
    tech_organization: $VALUE,
    tech_phone: $VALUE,
    tech_state: $VALUE,
    tech_zipcode: $VALUE,
    updated: $VALUE
}}
"""


if __name__ == "__main__":
    # load google supported tlds
    google_supported_domains = httpx.get(
        "https://www.google.com/supported_domains"
    ).text.split()

    # randomly chooses one and saves it
    # todo: this is just an example to get you started, please feel free to modify this
    #   to pull and save all or a subset of the domains.
    domain = random.choice(google_supported_domains)
    query_output, _ = asyncwhois.whois(domain, authoritative_only=True)
    # todo: after the first run, you can just read in this file without having to re-query the server.
    with open(f"./data/{domain}.txt", "w") as output:
        output.write(query_output)

    # get an LLM and give it the prompt
    llm = get_llm("mistral-nemo:12b")
    prompt = PromptTemplate(PROMPT_TEMPLATE).format(context_str=query_output)
    response = llm.complete(prompt)

    # save results
    with open(f"output_{domain}_{time.time_ns()}.txt", "w") as out:
        out.write(str(response))

    # todo: test the result! Feel free to manual/anecdotal or empirical methods.
