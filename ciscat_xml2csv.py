#!/usr/bin/python3

import xml.etree.ElementTree as etree
import itertools

tree = etree.parse('reports/ISMAD0216-report-20151218T090905Z.xml')
root = tree.getroot()

"""
First step is to build a dict with Rule ids and pass/fail results

<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
   <TestResult end-time="2015-12-18T10:10:51.776+01:00">
         <rule-result idref="xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Set_Enforce_password_history_to_24_or_more_passwords"
"""

result_dict = dict()  # contains pass/fail results

for child in root:  # iterate over root
    if 'TestResult' in child.tag:  # TestResult contains all the results
        for i in child:
            if 'rule-result' in i.tag:  # each rule-result contains one result
                idref = i.get('idref')  # Rule id
                for j in i:
                    if 'result' in j.tag:  # result
                        result_dict[idref] = j.text

"""
Second step is to parse all Groups and their content, and cross-reference with
the result dict for pass/fail/notselected result.

<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
    <Group id="xccdf_org.cisecurity.benchmarks_group_1_Account_Policies">
        <Group id="xccdf_org.cisecurity.benchmarks_group_1.1_Password_Policy">
            <Rule id="xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Set_Enforce_password_history_to_24_or_more_passwords">

"""

class Entry(object):
    def __init__(self, branch, number, control, result, description):
        self.branch = branch
        self.number = number
        self.control = control
        self.result = result
        self.description = description

def recursive_get_string(string, node):
    for i in node:
        if len(i) == 1:
            string += i.text
        else:
            string += recursive_get_string(string, i)
    return string

def recursive_iter_over_group(node):
    """
        As each group (branch) can contain either rules or sub-groups
        (sub-branches), we use a recursive function to iterate over each
        group/sub-group.
    """
    global count
    global entry_list
    for child in node:
        if 'title' in child.tag:
            test_title = child.text
        #elif 'description' in child.tag:
        #    test_description = child[0].text
        #    print('\t%s' % test_description)
        elif 'Rule' in child.tag:
            test_rule_id = child.get('id')
            for i in child:
                if 'title' in i.tag:
                    count += 1
                    test_rule_title = i.text
                if 'description' in i.tag:
                    #test_rule_description = ''.join(v.text for v in i)
                    test_rule_description = recursive_get_string('', i)

                    text = i[1].text
                    text = list(itertools.chain(*i))
                    text = list(itertools.chain.from_iterable(i))
                    print(type(text))
                    #text = ''.join(elem.text for elem in list(itertools.chain(*i)))



                test_rule_number = test_rule_id.split('_')[3]
                test_rule_result = result_dict[test_rule_id]
            print(test_title)
            print(text)
            #print(test_rule_number)
            #print(test_rule_title)
            #print(test_rule_result)
            #print(test_rule_description)
            print("")
            new_entry = Entry(test_title,
                              test_rule_number,
                              test_rule_title,
                              test_rule_result,
                              test_rule_description)
            entry_list.append(new_entry)
            break
        elif 'Group' in child.tag:
            recursive_iter_over_group(child)
            break
        elif 'description' in child.tag:
            test_description = child.text
        else:  # unhandled case
            print('[-] Unhandled tag %s.' % child.tag)

count = 0
entry_list = []
for child in root:  # iterate over root
    if 'Group' in child.tag:  # each Group is a branch
        recursive_iter_over_group(child)  # iterate over each group recursively
print('[+] Total rule count is %s.' % count)

print(len(entry_list))

# TODO get recursive text

"""
Third step is to create a csv file with all the info
"""
