import React, { useState, useEffect } from 'react';
import { Search, FileText, Database, TrendingUp, Users, Shield, Clock, Download, Upload, Play, AlertTriangle, CheckCircle, XCircle, Menu, X } from 'lucide-react';

const ForensicToolkit = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [evidenceList, setEvidenceList] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [analysisJobs, setAnalysisJobs] = useState([]);

  // Mock data initialization
  useEffect(() => {
    // Initialize with sample data
    const mockCases = [
      { id: '1', case_number: 'CASE-2025-001', title: 'Data Breach Investigation', status: 'in_progress', created_at: '2025-10-15', evidence_count: 15 },
      { id: '2', case_number: 'CASE-2025-002', title: 'Insider Threat Analysis', status: 'open', created_at: '2025-10-18', evidence_count: 8 },
      { id: '3', case_number: 'CASE-2025-003', title: 'Malware Incident Response', status: 'under_review', created_at: '2025-10-20', evidence_count: 22 }
    ];
    setCases(mockCases);

    const mockEvidence = [
      { id: '1', case_id: '1', evidence_number: 'EV-001', type: 'disk_image', description: 'Laptop hard drive image', size: '500 GB', collected_at: '2025-10-16' },
      { id: '2', case_id: '1', evidence_number: 'EV-002', type: 'memory_dump', description: 'RAM capture from server', size: '32 GB', collected_at: '2025-10-16' },
      { id: '3', case_id: '1', evidence_number: 'EV-003', type: 'log_file', description: 'Firewall logs', size: '2.5 GB', collected_at: '2025-10-17' }
    ];
    setEvidenceList(mockEvidence);

    const mockJobs = [
      { id: '1', name: 'File Carving Analysis', status: 'completed', progress: 100, artifacts: 1247 },
      { id: '2', name: 'Memory Artifact Extraction', status: 'running', progress: 67, artifacts: 0 },
      { id: '3', name: 'Timeline Generation', status: 'queued', progress: 0, artifacts: 0 }
    ];
    setAnalysisJobs(mockJobs);
  }, []);

  const StatusBadge = ({ status }) => {
    const colors = {
      open: 'bg-blue-100 text-blue-800',
      in_progress: 'bg-yellow-100 text-yellow-800',
      under_review: 'bg-purple-100 text-purple-800',
      closed: 'bg-gray-100 text-gray-800',
      completed: 'bg-green-100 text-green-800',
      running: 'bg-blue-100 text-blue-800',
      queued: 'bg-gray-100 text-gray-800'
    };
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[status] || colors.open}`}>
        {status.replace('_', ' ').toUpperCase()}
      </span>
    );
  };

  const Dashboard = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Active Cases</p>
              <p className="text-3xl font-bold text-gray-900">{cases.length}</p>
            </div>
            <FileText className="w-12 h-12 text-blue-500" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Evidence Items</p>
              <p className="text-3xl font-bold text-gray-900">{evidenceList.length}</p>
            </div>
            <Database className="w-12 h-12 text-green-500" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Analysis Jobs</p>
              <p className="text-3xl font-bold text-gray-900">{analysisJobs.length}</p>
            </div>
            <TrendingUp className="w-12 h-12 text-purple-500" />
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Artifacts Found</p>
              <p className="text-3xl font-bold text-gray-900">1,247</p>
            </div>
            <Shield className="w-12 h-12 text-red-500" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold mb-4">Recent Cases</h3>
          <div className="space-y-3">
            {cases.map(c => (
              <div key={c.id} className="flex items-center justify-between p-3 border rounded hover:bg-gray-50 cursor-pointer"
                onClick={() => { setSelectedCase(c); setActiveTab('cases'); }}>
                <div>
                  <p className="font-medium">{c.case_number}</p>
                  <p className="text-sm text-gray-600">{c.title}</p>
                </div>
                <StatusBadge status={c.status} />
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="text-lg font-semibold mb-4">Active Analysis Jobs</h3>
          <div className="space-y-4">
            {analysisJobs.map(job => (
              <div key={job.id} className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{job.name}</span>
                  <StatusBadge status={job.status} />
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="bg-blue-600 h-2 rounded-full transition-all" 
                    style={{ width: `${job.progress}%` }}></div>
                </div>
                <p className="text-xs text-gray-500">{job.progress}% complete</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  const CaseManagement = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Case Management</h2>
        <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          New Case
        </button>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Case Number</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Evidence</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {cases.map(c => (
              <tr key={c.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{c.case_number}</td>
                <td className="px-6 py-4 text-sm text-gray-900">{c.title}</td>
                <td className="px-6 py-4 whitespace-nowrap"><StatusBadge status={c.status} /></td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{c.evidence_count} items</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{c.created_at}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm">
                  <button className="text-blue-600 hover:text-blue-900 mr-3">View</button>
                  <button className="text-green-600 hover:text-green-900">Analyze</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const EvidenceManagement = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Evidence Management</h2>
        <button className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center gap-2">
          <Upload className="w-4 h-4" />
          Upload Evidence
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {evidenceList.map(evidence => (
          <div key={evidence.id} className="bg-white p-6 rounded-lg shadow">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div className="p-3 bg-blue-100 rounded-lg">
                  <Database className="w-6 h-6 text-blue-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">{evidence.evidence_number}</h3>
                  <p className="text-gray-600">{evidence.description}</p>
                  <div className="mt-2 flex gap-4 text-sm text-gray-500">
                    <span>Type: {evidence.type.replace('_', ' ')}</span>
                    <span>Size: {evidence.size}</span>
                    <span>Collected: {evidence.collected_at}</span>
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <button className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700">
                  Analyze
                </button>
                <button className="px-3 py-1 text-sm bg-gray-200 text-gray-700 rounded hover:bg-gray-300">
                  Download
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const AnalysisView = () => (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Forensic Analysis</h2>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <Shield className="w-10 h-10 text-blue-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">File Carving</h3>
          <p className="text-sm text-gray-600">Recover deleted files from disk images</p>
        </button>

        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <Database className="w-10 h-10 text-green-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">Memory Analysis</h3>
          <p className="text-sm text-gray-600">Extract artifacts from memory dumps</p>
        </button>

        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <Clock className="w-10 h-10 text-purple-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">Timeline Generation</h3>
          <p className="text-sm text-gray-600">Build forensic timeline from evidence</p>
        </button>

        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <Search className="w-10 h-10 text-red-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">Artifact Detection</h3>
          <p className="text-sm text-gray-600">AI-powered artifact identification</p>
        </button>

        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <AlertTriangle className="w-10 h-10 text-yellow-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">Malware Scan</h3>
          <p className="text-sm text-gray-600">Detect and analyze malicious files</p>
        </button>

        <button className="p-6 bg-white rounded-lg shadow hover:shadow-lg transition-shadow text-left">
          <TrendingUp className="w-10 h-10 text-indigo-600 mb-3" />
          <h3 className="font-semibold text-lg mb-2">Hash Analysis</h3>
          <p className="text-sm text-gray-600">Calculate and verify file hashes</p>
        </button>
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Analysis Results</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 border-l-4 border-green-500 bg-green-50">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-600" />
              <div>
                <p className="font-medium">File Carving Complete</p>
                <p className="text-sm text-gray-600">1,247 artifacts recovered</p>
              </div>
            </div>
            <button className="text-blue-600 hover:underline text-sm">View Details</button>
          </div>

          <div className="flex items-center justify-between p-3 border-l-4 border-blue-500 bg-blue-50">
            <div className="flex items-center gap-3">
              <Play className="w-5 h-5 text-blue-600" />
              <div>
                <p className="font-medium">Memory Analysis Running</p>
                <p className="text-sm text-gray-600">Processing... 67% complete</p>
              </div>
            </div>
            <div className="w-32 bg-gray-200 rounded-full h-2">
              <div className="bg-blue-600 h-2 rounded-full" style={{ width: '67%' }}></div>
            </div>
          </div>

          <div className="flex items-center justify-between p-3 border-l-4 border-yellow-500 bg-yellow-50">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
              <div>
                <p className="font-medium">Suspicious Files Detected</p>
                <p className="text-sm text-gray-600">12 high-risk items found</p>
              </div>
            </div>
            <button className="text-red-600 hover:underline text-sm font-medium">Investigate</button>
          </div>
        </div>
      </div>
    </div>
  );

  const TimelineView = () => (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Forensic Timeline</h2>

      <div className="bg-white p-6 rounded-lg shadow">
        <div className="flex gap-4 mb-6">
          <input type="date" className="px-4 py-2 border rounded-lg" />
          <input type="date" className="px-4 py-2 border rounded-lg" />
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            Filter
          </button>
        </div>

        <div className="space-y-4">
          {[
            { time: '2025-10-22 14:23:15', event: 'File Created', file: 'suspicious_document.pdf', type: 'creation' },
            { time: '2025-10-22 14:25:42', event: 'File Modified', file: 'system_config.ini', type: 'modification' },
            { time: '2025-10-22 14:30:18', event: 'Network Connection', file: '192.168.1.100:445', type: 'network' },
            { time: '2025-10-22 14:35:55', event: 'File Deleted', file: 'evidence_log.txt', type: 'deletion' },
            { time: '2025-10-22 14:40:12', event: 'Registry Modified', file: 'HKLM\\Software\\Microsoft', type: 'registry' }
          ].map((event, idx) => (
            <div key={idx} className="flex gap-4 items-start">
              <div className="flex flex-col items-center">
                <div className={`w-4 h-4 rounded-full ${
                  event.type === 'deletion' ? 'bg-red-500' :
                  event.type === 'creation' ? 'bg-green-500' :
                  event.type === 'network' ? 'bg-purple-500' : 'bg-blue-500'
                }`}></div>
                {idx < 4 && <div className="w-0.5 h-12 bg-gray-300"></div>}
              </div>
              <div className="flex-1 pb-4">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="font-medium">{event.event}</p>
                    <p className="text-sm text-gray-600">{event.file}</p>
                  </div>
                  <span className="text-sm text-gray-500">{event.time}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const ReportingView = () => (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Forensic Reports</h2>
        <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2">
          <FileText className="w-4 h-4" />
          Generate Report
        </button>
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Report Template</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Report Type</label>
            <select className="w-full px-4 py-2 border rounded-lg">
              <option>Comprehensive Investigation Report</option>
              <option>Executive Summary</option>
              <option>Technical Analysis Report</option>
              <option>Chain of Custody Report</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Case Selection</label>
            <select className="w-full px-4 py-2 border rounded-lg">
              {cases.map(c => (
                <option key={c.id}>{c.case_number} - {c.title}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Include Sections</label>
            <div className="space-y-2">
              {['Executive Summary', 'Case Overview', 'Evidence Analysis', 'Timeline', 'Findings', 'Recommendations'].map(section => (
                <label key={section} className="flex items-center gap-2">
                  <input type="checkbox" defaultChecked className="rounded" />
                  <span className="text-sm">{section}</span>
                </label>
              ))}
            </div>
          </div>

          <button className="w-full px-4 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center justify-center gap-2">
            <Download className="w-5 h-5" />
            Generate PDF Report
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Top Navigation */}
      <nav className="bg-blue-900 text-white shadow-lg">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button onClick={() => setSidebarOpen(!sidebarOpen)} className="lg:hidden">
                {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
              <Shield className="w-8 h-8" />
              <h1 className="text-xl font-bold">Digital Forensic Toolkit</h1>
            </div>
            <div className="flex items-center gap-4">
              <div className="hidden md:flex items-center gap-2 bg-blue-800 px-4 py-2 rounded-lg">
                <Users className="w-4 h-4" />
                <span className="text-sm">Lead Investigator</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0 fixed lg:static inset-y-0 left-0 z-30 w-64 bg-white shadow-lg transition-transform duration-300 ease-in-out`}>
          <nav className="p-4 space-y-2">
            {[
              { id: 'dashboard', icon: TrendingUp, label: 'Dashboard' },
              { id: 'cases', icon: FileText, label: 'Cases' },
              { id: 'evidence', icon: Database, label: 'Evidence' },
              { id: 'analysis', icon: Search, label: 'Analysis' },
              { id: 'timeline', icon: Clock, label: 'Timeline' },
              { id: 'reports', icon: Download, label: 'Reports' }
            ].map(item => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    activeTab === item.id
                      ? 'bg-blue-100 text-blue-700 font-medium'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 lg:p-8">
          {activeTab === 'dashboard' && <Dashboard />}
          {activeTab === 'cases' && <CaseManagement />}
          {activeTab === 'evidence' && <EvidenceManagement />}
          {activeTab === 'analysis' && <AnalysisView />}
          {activeTab === 'timeline' && <TimelineView />}
          {activeTab === 'reports' && <ReportingView />}
        </main>
      </div>
    </div>
  );
};

export default ForensicToolkit;