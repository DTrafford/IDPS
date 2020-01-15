import React from 'react';
import { hot } from 'react-hot-loader';
import '@fortawesome/fontawesome-free/css/all.min.css';
import 'bootstrap-css-only/css/bootstrap.min.css';
import 'mdbreact/dist/css/mdb.css';

import Home from './pages/Home';
// import SentryBoundary from './utils/SentryBoundary';

const App = () => <Home />;

export default hot(module)(App);
