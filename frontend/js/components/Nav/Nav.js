import React, { Component } from 'react';
import './Nav.css'
// const client = new W3CWebSocket('ws://localhost:8000/ws/ibsl/');

export default class Nav extends Component {
  render() {
    return (
      <span>
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark fixed-top" id="mainNav">
          <div className="container">
            <a className="navbar-brand js-scroll-trigger" href="#page-top">
              <span className="headerName">JIT -IDPS</span>
            </a>
            <button
              className="navbar-toggler"
              type="button"
              data-toggle="collapse"
              data-target="#navbarResponsive"
              aria-controls="navbarResponsive"
              aria-expanded="false"
              aria-label="Toggle navigation"
            >
              <span className="navbar-toggler-icon"></span>
            </button>
            <div className="collapse navbar-collapse" id="navbarResponsive">
              <ul className="navbar-nav ml-auto">
                <li className="nav-item">
                  {/* <a className="nav-link js-scroll-trigger" href="#about">
                    ABOUT
                  </a> */}
                  <button type="button" class="btn btn-outline-info buttonClass">ABOUT</button>
                </li>
                <li className="nav-item">
                  {/* <a className="nav-link js-scroll-trigger" href="#services">
                    START
                  </a> */}
                  <button type="button" class="btn btn-outline-success buttonClass" onClick={this.props.startSniffer}>START</button>
                </li>
                <li className="nav-item">
                  {/* <a className="nav-link js-scroll-trigger" href="#contact">
                    STOP
                  </a> */}
                  <button type="button" class="btn btn-outline-danger buttonClass">STOP</button>
                </li>
              </ul>
            </div>
          </div>
        </nav>
  
        <header className="bg-primary text-white" style={{height: '250px', padding: '20px 0 0 0'}}>
          <div className="container text-center" >
          <img src={require('../../../assets/img/network2.png')} alt="red cross" className="logoImage" />
          <div style={{paddingTop: '50px'}}>
            <h1>JIT - IDPS</h1>
            <p className="lead">
              Safety in the palm of your hands
            </p>
            </div>
          </div>
        </header>
      </span>
    );
  }
}

