# Outdated, tests no longer are suited for current version of probAssess.py


import unittest
import probAssess

from sys import argv
filename = argv[1]
test_results = [['CVE-2019-0190', 'l'], ['CVE-2012-1873', 'm'], ['CVE-2011-2834', 'h']]
define_nodes_test = [[1, 2, 3, 4, 6, 7, 8, 9, 11], [2, 4, 7, 9], [1, 3, 6, 8], 11]
define_edges_test = [[9,11], [8,9], [7,8], [6,7], [4,6], [3,4], [2,3], [1,2]]

chi_n_test_nodes = [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [4, 5, 9, 10, 6, 7], [11, 8, 2, 3], 1]
chi_n_test_edges = [[2, 1], [3, 1], [7, 3], [6, 3], [4, 2], [5, 2], [8, 5], [9, 8], [10, 8], [11, 10]] 

delta_n_test_edges = [[2, 1], [3, 1], [4, 2], [5, 4], [6, 4], [7, 3], [7, 5], [8, 6], [9, 7], [10, 8], [11, 9], [11, 10]]
delta_n_test_nodes = [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], [2, 3, 5, 6, 9, 10], [11, 7, 8, 4, 1], 1]

class probAssessTests(unittest.TestCase):
        def test_no_cvss_info(self):
                self.assertEqual(probAssess.list_vuls("no_cvss.P"), None)
	def test_record_cvss_info(self):
		self.assertEqual(probAssess.list_vuls("vul_list_test.P"), test_results)
	def test_define_nodes(self):
		self.assertEqual(probAssess.define_nodes("NODE_TEST.CSV"), define_nodes_test)
	def test_define_edges(self):
		self.assertEqual(probAssess.define_edges("ARC_TEST.CSV", define_nodes_test[0]), define_edges_test)
	def test_chi_n(self):
		t = probAssess.chi_n(11, chi_n_test_nodes, [2, 3, 8], [10], chi_n_test_edges)
		self.assertEqual(sorted([8, 2]), sorted(t))
	def test_delta_n(self):
		self.assertEqual([1], probAssess.delta_n(11, delta_n_test_nodes, [1, 4], [9, 10], delta_n_test_edges))
	def test_D_set(self):
		D_set_chi_table = [[0, []], [1, []], [2, [1]], [3, [1]], [4, [1]], [5, [4, 1]], [6, [4, 1]]]
		self.assertEqual(sorted(probAssess.find_D_set([1, 2, 3, 4, 5, 6], D_set_chi_table)), sorted([4, 1]))
	def test_Cond_Prob1(self):
		#Test on single node
		self.assertEqual(probAssess.evalCondProb([1], [1], [0, 1], [[1], [], [1], [1]], []), 1)
	def test_Cond_Prob2(self):
		self.assertEqual(probAssess.evalCondProb([1], [1], [0, 0], [[1], [], [1], [1]], []), 0)
	def test_Cond_Prob3(self):
		self.assertEqual(probAssess.evalCondProb([1], [1, 2, 3], [0, 1, 1, 1], [[1, 2, 3], [2, 3], [1], [1]], [[2, 1], [3, 1]]), 1)
	def test_evalProb(self):
		self.assertEqual(probAssess.evalProb([1, 2, 3], [0, 1, 1, 1], [[1, 2, 3], [2, 3], [1], [1]], [[2, 1], [3, 1]]), 0.5625)
	def test_evalProb2(self):
		self.assertEqual(probAssess.evalProb([], [0, 0, 0, 0], [[1, 2, 3], [2, 3], [1], [1]], [[1, 2], [1, 3]]), 0.5625)
	def test_integrate_cvss(self):
		self.assertEqual(probAssess.integrate_cvss("vulnerabilities.txt", "NODE_TEST.CSV", "ARC_TEST.CSV", [[1, 2, 3, 4, 5, 6, 7, 8]]), [None, None, 0.3, None, None, None, None, 0.3, None, None, None, None, None, 0.3, None, 0.3])

	
