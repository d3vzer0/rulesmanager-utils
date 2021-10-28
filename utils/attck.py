import json
import aiohttp
import asyncio
from .reternalapi import ReternalAPI

def load_magma(path='../mitre/magma_mapping.json'):
    magma_mapping = { }
    with open(path, 'r') as magma_file:
        json_object = json.loads(magma_file.read())
        for mapping in json_object:
            magma_mapping[mapping['external_id']] = mapping
    return magma_mapping


class Technique:
    def __init__(self, technique):
        self.technique = technique

    @classmethod
    def from_cti(cls, technique):
        ''' Format technique to match expected API schema '''
        technique = { 
            'cti_id': technique['id'],
            'name':technique['name'],
            'technique': technique['external_references'][0]['external_id'],
            'description': technique['description'],
            'platforms': [platform for platform in technique['x_mitre_platforms']], 
            'permissions_required': [permission for permission in technique.get('x_mitre_permissions_required', [])],
            'data_sources': [datasource for datasource in technique.get('x_mitre_data_sources', [])],
            'references': technique['external_references'],
            'kill_chain_phases': [phase['phase_name'] for phase in technique['kill_chain_phases']],
            'is_subtechnique': technique.get('x_mitre_is_subtechnique', False),
        }
        return cls(technique)

    def set_magma(self, magma_mapping):
        external_id = self.technique['external_references'][0]['external_id']
        if external_id in self.magma_mapping:
            mapped_usecase = self.magma_mapping[external_id]
            mapped_usecase.pop('external_id')
            self.technique['magma'] = mapped_usecase


class Actor:
    def __init__(self, actor):
        self.actor = actor

    @classmethod
    def from_cti(cls, actor):
        actor = {
            'cti_id': actor['id'], 
            'name': actor['name'],
            'references': actor['external_references'],
            'aliases': [alias for alias in \
                actor.get('aliases', [])],
            'description': actor.get('description', None),
            'techniques': []
        }
        return cls(actor)


class Relationship:
    def __init__(self, relationship):
        self.relationship = relationship

    @classmethod
    def from_cti(cls, relationship):
        relationship = {
            'source_ref': relationship['source_ref'], 
            'target_ref': relationship['target_ref'],
        }
        return cls(relationship)

class MitreAttck:
    def __init__(self, cti_objects = None):
        self.cti_objects = cti_objects

    @property
    def actors(self):
        for entry in self.cti_objects:
            if entry['type'] == 'intrusion-set':
                    yield Actor.from_cti(entry)
    @property
    def techniques(self):
        for entry in self.cti_objects:
            if entry['type'] == 'attack-pattern':
                yield Technique.from_cti(entry)

    @property
    def relationships(self):
        for entry in self.cti_objects:
            if entry['type'] == 'relationship':
                if 'intrusion' in entry['source_ref'] and 'attack-pattern' in entry['target_ref']:
                    yield Relationship.from_cti(entry)

    @classmethod
    async def from_cti(cls, cti_url='https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'):
        # Since github does not return a valid json response header
        # we have to load the response as text first and parse afterwards
        async with aiohttp.ClientSession() as session:
            async with session.get(cti_url) as resp:
                get_entries = await resp.text()

        cti_objects = []
        for entry in json.loads(get_entries)['objects']:
            if entry.get('revoked', False) == False:
                cti_objects.append(entry)
   
        return cls(cti_objects=cti_objects)


async def import_attck(*args, **kwargs):
    ''' Retrieve MITRE ATTCK database and format data '''
    mitre_attck = await MitreAttck.from_cti(kwargs['cti_url'])
    async with ReternalAPI(api_url=kwargs['api_url']) as reternal:
        for technique in mitre_attck.techniques:
            await reternal.save('/techniques', technique.technique)
       
        for actor in mitre_attck.actors:
            await reternal.save('/actors', actor.actor)

        for relationship in mitre_attck.relationships:
            await reternal.save('/relationships', relationship.relationship)

if __name__ == "__main__":
    asyncio.run(import_attck())
