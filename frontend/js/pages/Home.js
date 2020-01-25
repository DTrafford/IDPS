import React, { Component } from 'react';
import { w3cwebsocket as W3CWebSocket } from 'websocket';
import Nav from '../components/Nav/Nav.js';
import Nav2 from '../components/Nav/Nav2.js';
import Container from './ResuableContainer';
import Alerts from '../components/Alerts/Alerts';
import Footer from '../components/Footer/Footer';
const client = new W3CWebSocket('ws://localhost:8000/ws/idps/');

import PacketsTable from '../components/MaterialUI/PacketsTable'

class Home extends Component {
  state = {
    message: '',
    packets: [],
    alerts: [],
    testArray: [
      {'pckt_src': '104.20.62.122', 'pckt_dst': '192.168.0.191', 'srcCountry': 'United States', 'dstCountry': 'United States', 'time': '2019-11-25 21:29:49', 'src_port': 443, 'dst_port': 51760}
    ],
    notify: ''
  };
  componentWillMount() {
    client.onopen = () => {
      console.log('WebSocket Client Connected');
    };
    client.onmessage = (message) => {
      let data = JSON.parse(message.data);
      if (this.state.message !== data.message) {
        var joinedPackets = this.state.packets.concat(data.message);

        this.setState({
          message: data.message,
          packets: joinedPackets
        });
      }
      if (data.hasOwnProperty('notify') && this.state.notify !== data.notify) {
        this.setState({
          notify: data.notify !== "" ? data.notify : this.state.notify,
        });
      }
    };
  }
  // componentDidMount = () => {
  //   console.log(this.state.testArray[0].pckt_src);
  // }
  componentWillUnmount() {
    client.close();
  }
  //  sendToPython = (r) => {
  //    client.send(
  //      JSON.stringify({
  //        message: r.target.value,
  //      })
  //    );
  //  };
  sendStartCommand = (r) => {
    console.log('IN START');
    client.send(
      JSON.stringify({
        message: 'start',
      })
    );
  };
  sendStopCommand = (r) => {
    client.send(
      JSON.stringify({
        message: 'stop',
      })
    );
  };

  render() {
    return (
      <div className="box">
        <Nav2 startSniffer={this.sendStartCommand} />
        <div style={{marginTop: '100px'}}></div>
        <Alerts />
        {/* <section id="about">
          <div className="container">
            <div className="row">
              <div className="col-lg-8 mx-auto">
                <h2>Python packer Tracer</h2>

                <button className="btn btn-info" onClick={() => this.sendStartCommand()}>
                  {' '}
                  Start
                </button>
                <button className="btn btn-danger" onClick={() => this.sendStopCommand()}>
                  {' '}
                  SOP
                </button>
                </div>
              </div>
            </div>
        </section> */}
        <PacketsTable packets={this.state.packets}/>
        <Footer />
      </div>
    );
  }
}

export default Home;
