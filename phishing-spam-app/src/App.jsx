import { useState } from 'react';
import axios from 'axios';
import {
  AppBar, Toolbar, Typography, TextField, Button,
  Card, CardContent, Box, Input, CssBaseline, ThemeProvider,
  createTheme, Tabs, Tab
} from '@mui/material';
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { Grid } from '@mui/material';
import { Dialog, DialogContent, CircularProgress } from '@mui/material';


function App() {
  const [url, setUrl] = useState('');
  const [urlResult, setUrlResult] = useState('');

  const [emailFiles, setEmailFiles] = useState([]);
  const [emailResults, setEmailResults] = useState([]);
  const [insights, setInsights] = useState(null);

  const [fakeUrl, setFakeUrl] = useState('');
  const [activeTab, setActiveTab] = useState(0);
  const [analyzing, setAnalyzing] = useState(false); // For loading dialog


  const handleTabChange = (event, newValue) => {
    setActiveTab(newValue);
    resetStates();
  };

  const resetStates = () => {
    setUrl('');
    setUrlResult('');
    setFakeUrl('');
    setEmailFiles([]);
    setEmailResults([]);
    setInsights(null);
  };
  
  const handleUrlCheck = async () => {
    try {
      const response = await axios.post('http://localhost:5000/api/check_url', { url });
  
      setUrlResult({
        status: response.data.result,         // "Phishing" or "Safe"
        type: response.data.phishing_type     // "Urgency Phishing", "Reward Phishing", etc
      });
    } catch (error) {
      console.error(error);
    }
  };
  

  const handleFileUpload = async () => {
    if (!emailFiles.length) return;
    
    const formData = new FormData();
    for (let file of emailFiles) {
      formData.append('files', file);
    }
  
    try {
      setAnalyzing(true); // 👉 Start loader
      const response = await axios.post('http://localhost:5000/api/check_spam', formData);
      setEmailResults(response.data.results);
      setInsights(response.data.insights);
    } catch (error) {
      console.error(error);
    } finally {
      setAnalyzing(false); // 👉 Stop loader
    }
  };
  

  const handleFakeSimulation = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/generate_fake_url');
      setFakeUrl(`http://localhost:5000${response.data.fake_url}`);
    } catch (error) {
      console.error(error);
    }
  };

  const handleGenerateReport = async () => {
    try {
      const formData = new FormData();
      for (let file of emailFiles) {
        formData.append('files', file);
      }
  
      const response = await axios.post('http://localhost:5000/api/generate_pdf_report', formData, {
        responseType: 'blob',  // Important to receive it as a binary Blob
      });
  
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
  
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'spam_detection_report.pdf');
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('Error generating PDF:', error);
    }
  };
  

  const theme = createTheme({
    palette: {
      mode: 'dark',
      primary: { main: '#2196f3' },
      secondary: { main: '#9c27b0' },
      warning: { main: '#ff9800' },
      background: { default: '#121212', paper: '#1e1e1e' }
    },
  });

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
  
      <Box
        sx={{
          width: '100vw',
          height: '100vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          backgroundImage: 'url(/background.gif)',  // <-- LOCAL file reference
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          backgroundAttachment: 'fixed',
        }}
      >
<AppBar
  position="static"
  color="default"
  elevation={6}
  sx={{
    width: '100%',
    background: 'linear-gradient(to right, #5a0000, #7d0022)',  // Darker red-pink gradient
    py: 1,
    boxShadow: '0 6px 18px rgba(0,0,0,0.8)',  // Darker, deeper shadow
  }}
>
  <Toolbar sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', px: 4 }}>
    
    {/* Title */}
    <Typography 
      variant="h6" 
      sx={{ 
        fontWeight: 'bold', 
        letterSpacing: 1,
        color: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        fontSize: '1.25rem',
      }}
    >
      🛡️ <span style={{ marginLeft: '8px' }}>InvisiGuard</span>
    </Typography>
    
    {/* Tabs */}
    <Tabs
      value={activeTab}
      onChange={handleTabChange}
      textColor="inherit"
      TabIndicatorProps={{ style: { backgroundColor: '#ffc107', height: '4px', borderRadius: '2px' } }}
      sx={{
        '.MuiTab-root': { fontWeight: 'bold', fontSize: '1rem', mx: 1, color: '#eeeeee' },
        '.Mui-selected': { color: '#ffc107' },
      }}
    >
      <Tab label="Phishing Detection" />
      <Tab label="Email Spam Detection" />
    </Tabs>

  </Toolbar>
</AppBar>


  
      <Box
  sx={{
    flexGrow: 1,
    width: '100%',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    overflow: 'hidden',
    p: { xs: 2, sm: 4 },
  }}
>
  <Box
    sx={{
      position: 'relative',
      width: '95%',
      maxWidth: '1100px',
      aspectRatio: '16/9',
      backgroundColor: 'background.paper',
      borderRadius: 4,
      boxShadow: 8,
      p: { xs: 2, sm: 4 },
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      overflow: 'auto',
    }}
  >
    <Card sx={{ width: '100%', height: '100%', boxShadow: 'none', background: 'transparent' }}>
      <CardContent sx={{ height: '100%', overflowY: 'auto' }}>

        {/* Phishing Detection Section */}
        {activeTab === 0 && (
          <>
            <Typography variant="h4" align="center" sx={{ mb: 4, fontWeight: 'bold' }}>
              🔗 Phishing URL Checker
            </Typography>

            <Box display="flex" flexDirection={{ xs: 'column', sm: 'row' }} gap={2} mb={4}>
              <TextField
                fullWidth
                label="Enter URL"
                variant="outlined"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <Button variant="contained" color="primary" onClick={handleUrlCheck} sx={{ whiteSpace: 'nowrap' }}>
                Check
              </Button>
            </Box>

            {urlResult && (
              <Typography align="center" sx={{ fontWeight: 'bold', mb: 4, fontSize: '1.2rem' }}>
                Result: {urlResult.status === 'Phishing' ? (
                  <span style={{ color: 'red' }}>{urlResult.status} - {urlResult.type}</span>
                ) : (
                  <span style={{ color: 'lightgreen' }}>{urlResult.status}</span>
                )}
              </Typography>
            )}


            <Box textAlign="center">
              <Button variant="contained" color="warning" onClick={handleFakeSimulation}>
                🎭 Generate Fake Phishing Link
              </Button>
              {fakeUrl && (
                <Typography sx={{ mt: 2 }}>
                  <a href={fakeUrl} target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9' }}>
                    {fakeUrl}
                  </a>
                </Typography>
              )}
            </Box>
          </>
        )}

        {/* Email Spam Detection Section */}
        {activeTab === 1 && (
          <>
            <Typography variant="h4" align="center" sx={{ mb: 4, fontWeight: 'bold' }}>
              📧 Email Spam Detection
            </Typography>

            <Box display="flex" flexDirection={{ xs: 'column', sm: 'row' }} gap={2} mb={4}>
              <Input
                type="file"
                fullWidth
                inputProps={{ multiple: true }}
                onChange={(e) => setEmailFiles(Array.from(e.target.files))}
                sx={{ color: 'white' }}
              />
              <Button variant="contained" color="secondary" onClick={handleFileUpload} sx={{ whiteSpace: 'nowrap' }}>
                Analyze
              </Button>
            </Box>
            <Dialog
              open={analyzing}
              PaperProps={{
                sx: {
                  borderRadius: 4,    // <-- Rounded corners
                  p: 2,
                  minWidth: 300,       // (optional) if you want a minimum width
                }
              }}
            >
              <DialogContent sx={{ textAlign: 'center', p: 5 }}>
                <CircularProgress size={60} />
                <Typography variant="h6" sx={{ mt: 3 }}>
                  Analyzing emails...
                </Typography>
              </DialogContent>
            </Dialog>
            {/* Analysis Results */}
            {emailResults.length > 0 && (
              <>
                <Typography variant="h6" align="center" sx={{ mb: 3, fontWeight: 'bold' }}>
                  📄 Analysis Results
                </Typography>

                {/* Results Table */}
                <TableContainer component={Paper} sx={{ backgroundColor: 'background.paper', boxShadow: 4 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Filename</strong></TableCell>
                        <TableCell align="center"><strong>Result</strong></TableCell>
                        <TableCell align="center"><strong>Accuracy Score (%)</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {emailResults.map((result, idx) => (
                        <TableRow key={idx}>
                          <TableCell>{result.filename}</TableCell>
                          <TableCell
                            align="center"
                            sx={{ fontWeight: 'bold', color: result.spam_result === 'SPAM' ? 'red' : 'lightgreen' }}
                          >
                            {result.spam_result}
                          </TableCell>
                          <TableCell align="center">
                            {result.confidence_score !== undefined && result.confidence_score !== null
                              ? `${result.confidence_score}%`
                              : 'N/A'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>

                {/* IP Geolocation Section */}
                <Typography variant="h6" align="center" sx={{ mt: 6, mb: 3, fontWeight: 'bold' }}>
                  🌍 Extracted IP Addresses and Locations
                </Typography>

                <TableContainer component={Paper} sx={{ backgroundColor: 'background.paper', boxShadow: 4 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell><strong>Filename</strong></TableCell>
                        <TableCell><strong>IP Address</strong></TableCell>
                        <TableCell><strong>City</strong></TableCell>
                        <TableCell><strong>Country</strong></TableCell>
                        <TableCell><strong>ISP</strong></TableCell>
                        <TableCell align="center"><strong>View on Map</strong></TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {emailResults.flatMap((result, idx) =>
                        result.geolocation_info.map((geo, ipIdx) => (
                          <TableRow key={`${idx}-${ipIdx}`}>
                            <TableCell>{result.filename}</TableCell>
                            <TableCell>{geo.ip}</TableCell>
                            <TableCell>{geo.city || 'Unknown'}</TableCell>
                            <TableCell>{geo.country || 'Unknown'}</TableCell>
                            <TableCell>{geo.isp || 'Unknown'}</TableCell>
                            <TableCell align="center">
                              {geo.google_maps_link ? (
                                <a href={geo.google_maps_link} target="_blank" rel="noopener noreferrer" style={{ color: '#90caf9' }}>
                                  Open
                                </a>
                              ) : (
                                'N/A'
                              )}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>

                {/* Insights Section */}
                {insights && (
                  <Box mt={5}>
                    <Typography variant="h6" align="center" sx={{ mb: 3, fontWeight: 'bold' }}>
                      📊 Overall Detection Summary
                    </Typography>

                    <Grid container spacing={2} justifyContent="center">
                      <Grid item xs={12} sm={4}>
                        <Card sx={{ p: 2, backgroundColor: 'background.paper', textAlign: 'center', boxShadow: 2 }}>
                          <Typography variant="subtitle2" color="textSecondary">Total Files</Typography>
                          <Typography variant="h6" sx={{ mt: 1, fontWeight: 'bold' }}>
                            {insights.total_files_analyzed}
                          </Typography>
                        </Card>
                      </Grid>

                      <Grid item xs={12} sm={4}>
                        <Card sx={{ p: 2, backgroundColor: 'background.paper', textAlign: 'center', boxShadow: 2 }}>
                          <Typography variant="subtitle2" color="textSecondary">Spam Detected</Typography>
                          <Typography variant="h6" sx={{ mt: 1, color: 'red', fontWeight: 'bold' }}>
                            {insights.spam_files_detected} ({insights.spam_percentage}%)
                          </Typography>
                        </Card>
                      </Grid>

                      <Grid item xs={12} sm={4}>
                        <Card sx={{ p: 2, backgroundColor: 'background.paper', textAlign: 'center', boxShadow: 2 }}>
                          <Typography variant="subtitle2" color="textSecondary">Safe Detected</Typography>
                          <Typography variant="h6" sx={{ mt: 1, color: 'lightgreen', fontWeight: 'bold' }}>
                            {insights.safe_files_detected} ({insights.safe_percentage}%)
                          </Typography>
                        </Card>
                      </Grid>
                    </Grid>
                  <Button
                    variant="contained"
                    color="warning"
                    size="large"
                    sx={{ mt: 4, fontWeight: 'bold', px: 5 }}
                    onClick={handleGenerateReport}
                  >
                    📄 Generate PDF Report
                  </Button>
                </Box>
                
                )}
              </>
            )}
          </>
        )}

      </CardContent>

            </Card>
          </Box>
        </Box>
      </Box>
    </ThemeProvider>
  );
}

export default App;
