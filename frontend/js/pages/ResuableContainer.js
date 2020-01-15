import React from 'react';

const Container = (props) => {
  return (
    <section id={props.id} className={props.class}>
      <div className="container">
        <div className="row">
          <div className="col-lg-8 mx-auto">
            <h2>{props.heading}</h2>
            <p className="lead">{props.text}</p>
          </div>
        </div>
      </div>
    </section>
  );
};

export default Container;
